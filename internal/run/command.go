package run

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path"
	"strings"
	"time"

	"github.com/ikkun1222/trustless/internal/audit"
	"github.com/ikkun1222/trustless/internal/backend"
	"github.com/ikkun1222/trustless/internal/config"
	"github.com/ikkun1222/trustless/internal/scanner"
)

type stringSlice []string

func (s *stringSlice) String() string { return strings.Join(*s, ",") }
func (s *stringSlice) Set(v string) error {
	*s = append(*s, v)
	return nil
}

type runResult struct {
	ExitCode int    `json:"exit_code"`
	Stdout   string `json:"stdout"`
	Stderr   string `json:"stderr"`
}

func CheckPolicy(cmdName string, secretKeys []string, policy config.PolicyConfig) error {
	for _, key := range secretKeys {
		for _, override := range policy.Overrides {
			if override.SecretKey == key {
				for _, denied := range override.DeniedCommands {
					if cmdName == denied {
						return fmt.Errorf("policy violation: credential %q is not allowed with command %q", key, cmdName)
					}
				}
			}
		}
	}
	for _, denied := range policy.Default.DeniedCommands {
		if cmdName == denied {
			return fmt.Errorf("policy violation: command %q is denied by default policy", cmdName)
		}
	}
	return nil
}

func Run(args []string, be backend.Backend, cfg *config.Config) {
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	var secrets stringSlice
	fs.Var(&secrets, "s", "Credential key to inject (repeatable, format: KEY or KEY:ENVNAME)")
	fs.Var(&secrets, "secret", "Credential key to inject (repeatable, format: KEY or KEY:ENVNAME)")
	jsonOutput := fs.Bool("json", false, "Output results as JSON")
	timeoutStr := fs.String("timeout", "", "Subprocess timeout (e.g. \"30s\", \"5m\")")

	sanitizeFlag := fs.Bool("sanitize", true, "Enable output sanitization (default: true)")
	sanitizePolicy := fs.String("sanitize-policy", "", "Path to custom redaction patterns file")
	scanArgs := fs.Bool("scan-args", true, "Scan command arguments for credential patterns before spawning (fail closed)")

	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "Usage: trustless run [flags] [--] <command> [args...]")
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "Run a command with credentials injected as environment variables.")
		fmt.Fprintln(os.Stderr, "Credentials are resolved from the pass store and set on the subprocess.")
		fmt.Fprintln(os.Stderr, "Output is scanned for credential patterns and redacted.")
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "Flags:")
		fs.PrintDefaults()
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "Examples:")
		fmt.Fprintln(os.Stderr, "  trustless run -s iria/api/xai -- curl -s https://api.x.ai/v1/models")
		fmt.Fprintln(os.Stderr, "  trustless run --json -s iria/api/xai -s iria/api/openrouter -- sh -c 'echo done'")
	}

	if err := fs.Parse(args); err != nil {
		os.Exit(2)
	}

	cmdArgs := fs.Args()
	if len(cmdArgs) == 0 {
		fmt.Fprintln(os.Stderr, "Error: no command specified")
		os.Exit(2)
	}

	secretKeys := extractSecretKeys(secrets)
	cmdBase := path.Base(cmdArgs[0])
	if err := CheckPolicy(cmdBase, secretKeys, cfg.Policy); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(3)
	}

	ctx, cancel := buildContext(*timeoutStr)
	defer cancel()

	env, credValues := resolveSecrets(ctx, secrets, be)

	sanitize := *sanitizeFlag && cfg.RunDefaults.Sanitize
	s := buildScanner(sanitize, cfg, *sanitizePolicy)

	if *scanArgs && s != nil {
		if s.ContainsCredentials([]byte(strings.Join(cmdArgs, " ")), credValues) {
			fmt.Fprintln(os.Stderr, "Error: command arguments contain credential patterns. Blocked by --scan-args.")
			fmt.Fprintln(os.Stderr, "Use --scan-args=false to disable this check (not recommended).")
			os.Exit(3)
		}
	}

	cmd := exec.CommandContext(ctx, cmdArgs[0], cmdArgs[1:]...)
	cmd.Env = env

	// 監査: 子プロセス起動を記録（値は含めない・コマンド名と引数のみ）
	kind := cfg.Audit.Sink
	if kind == "" {
		kind = "file"
	}
	sink := audit.New(kind, cfg.Audit.File, cfg.Audit.Buffer)
	defer sink.Close()
	sink.Emit(audit.Event{
		TS:      time.Now(),
		Event:   audit.RunSpawn,
		Verdict: audit.VerdictSpawn,
		Detail:  fmt.Sprintf("cmd=%s args=%d", path.Base(cmdArgs[0]), len(cmdArgs)-1),
	})

	if *jsonOutput {
		runJSON(cmd, sanitize, s, credValues)
	} else {
		runPassthrough(cmd, sanitize, s, credValues)
	}
}

func envVarName(key string) string {
	last := path.Base(key)
	last = strings.ReplaceAll(last, "-", "_")
	return strings.ToUpper(last)
}

func extractSecretKeys(secrets stringSlice) []string {
	var keys []string
	for _, spec := range secrets {
		if colon := strings.Index(spec, ":"); colon >= 0 {
			keys = append(keys, spec[:colon])
		} else {
			keys = append(keys, spec)
		}
	}
	return keys
}

func buildContext(timeoutStr string) (context.Context, context.CancelFunc) {
	ctx := context.Background()
	if timeoutStr == "" {
		return ctx, func() {}
	}
	d, err := time.ParseDuration(timeoutStr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: invalid timeout: %v\n", err)
		os.Exit(2)
	}
	return context.WithTimeout(ctx, d)
}

func resolveSecrets(ctx context.Context, secrets stringSlice, be backend.Backend) ([]string, []string) {
	env := os.Environ()
	var credValues []string
	for _, spec := range secrets {
		var secretKey, envName string
		if colon := strings.Index(spec, ":"); colon >= 0 {
			secretKey = spec[:colon]
			envName = spec[colon+1:]
		} else {
			secretKey = spec
			envName = envVarName(spec)
		}
		val, err := be.Resolve(ctx, secretKey)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(2)
		}
		env = append(env, envName+"="+val)
		credValues = append(credValues, val)
	}
	return env, credValues
}

func buildScanner(sanitize bool, cfg *config.Config, sanitizePolicy string) *scanner.Scanner {
	if !sanitize {
		return nil
	}
	s := scanner.New()
	for _, p := range cfg.Sanitize.Patterns {
		if err := s.AddPattern(p); err != nil {
			fmt.Fprintf(os.Stderr, "Error: invalid pattern in config: %v\n", err)
			os.Exit(2)
		}
	}
	if sanitizePolicy != "" {
		data, err := os.ReadFile(sanitizePolicy)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: reading sanitize policy: %v\n", err)
			os.Exit(2)
		}
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			if err := s.AddPattern(line); err != nil {
				fmt.Fprintf(os.Stderr, "Error: invalid pattern in policy file: %v\n", err)
				os.Exit(2)
			}
		}
	}
	return s
}

// sanitizingWriter streams child output through the credential scanner line by
// line. Unlike the old buffered approach, long-running processes (ACP servers,
// gateways) get their output flushed in real time instead of only at exit.
type sanitizingWriter struct {
	dst    io.Writer
	s      *scanner.Scanner
	values []string
	buf    bytes.Buffer
}

func (w *sanitizingWriter) Write(p []byte) (int, error) {
	w.buf.Write(p)
	for {
		i := bytes.IndexByte(w.buf.Bytes(), '\n')
		if i < 0 {
			break
		}
		line := w.buf.Next(i + 1)
		if _, err := w.dst.Write(w.s.ScanWithValues(line, w.values)); err != nil {
			return len(p), err
		}
	}
	return len(p), nil
}

func (w *sanitizingWriter) Flush() error {
	if w.buf.Len() == 0 {
		return nil
	}
	scanned := w.s.ScanWithValues(w.buf.Bytes(), w.values)
	w.buf.Reset()
	_, err := w.dst.Write(scanned)
	return err
}

func runPassthrough(cmd *exec.Cmd, sanitize bool, s *scanner.Scanner, extraValues []string) {
	cmd.Stdin = os.Stdin
	var outW, errW *sanitizingWriter
	if sanitize {
		outW = &sanitizingWriter{dst: os.Stdout, s: s, values: extraValues}
		errW = &sanitizingWriter{dst: os.Stderr, s: s, values: extraValues}
		cmd.Stdout = outW
		cmd.Stderr = errW
	} else {
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
	}
	if err := cmd.Run(); err != nil {
		if outW != nil {
			outW.Flush()
		}
		if errW != nil {
			errW.Flush()
		}
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			os.Exit(exitErr.ExitCode())
		}
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	if outW != nil {
		outW.Flush()
	}
	if errW != nil {
		errW.Flush()
	}
}

func runJSON(cmd *exec.Cmd, sanitize bool, s *scanner.Scanner, extraValues []string) {
	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	stderrPipe, err := cmd.StderrPipe()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	if err := cmd.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	stdout, _ := io.ReadAll(stdoutPipe)
	stderr, _ := io.ReadAll(stderrPipe)

	if sanitize {
		stdout = s.ScanWithValues(stdout, extraValues)
		stderr = s.ScanWithValues(stderr, extraValues)
	}

	exitCode := 0
	if err := cmd.Wait(); err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			exitCode = exitErr.ExitCode()
		} else {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
	}

	res := runResult{
		ExitCode: exitCode,
		Stdout:   string(stdout),
		Stderr:   string(stderr),
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(res); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}
