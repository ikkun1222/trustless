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

	"github.com/ikkun1222/trustless/internal/backend"
	"github.com/ikkun1222/trustless/internal/config"
	"github.com/ikkun1222/trustless/internal/scanner"
)

type stringSlice []string

func (s *stringSlice) String() string  { return strings.Join(*s, ",") }
func (s *stringSlice) Set(v string) error {
	*s = append(*s, v)
	return nil
}

type runResult struct {
	ExitCode int    `json:"exit_code"`
	Stdout   string `json:"stdout"`
	Stderr   string `json:"stderr"`
}

func Run(args []string, be backend.Backend, cfg *config.Config) {
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	var secrets stringSlice
	fs.Var(&secrets, "s", "credential key to inject (repeatable)")
	fs.Var(&secrets, "secret", "credential key to inject (repeatable)")
	jsonOutput := fs.Bool("json", false, "output results as JSON")
	timeoutStr := fs.String("timeout", "", "subprocess timeout (e.g. \"30s\", \"5m\")")

	sanitizeFlag := fs.Bool("sanitize", true, "enable output sanitization")
	sanitizePolicy := fs.String("sanitize-policy", "", "path to file with custom redaction patterns")

	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "Usage: trustless run [flags] [--] <command> [args...]")
		fs.PrintDefaults()
	}

	if err := fs.Parse(args); err != nil {
		os.Exit(2)
	}

	cmdArgs := fs.Args()
	if len(cmdArgs) == 0 {
		fmt.Fprintln(os.Stderr, "Error: no command specified")
		os.Exit(2)
	}

	ctx := context.Background()
	if *timeoutStr != "" {
		d, err := time.ParseDuration(*timeoutStr)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: invalid timeout: %v\n", err)
			os.Exit(2)
		}
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, d)
		defer cancel()
	}

	env := os.Environ()
	var credValues []string
	for _, key := range secrets {
		val, err := be.Resolve(ctx, key)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(2)
		}
		envName := envVarName(key)
		env = append(env, envName+"="+val)
		credValues = append(credValues, val)
	}

	sanitize := *sanitizeFlag && cfg.RunDefaults.Sanitize

	var s *scanner.Scanner
	if sanitize {
		s = scanner.New()
		for _, p := range cfg.Sanitize.Patterns {
			if err := s.AddPattern(p); err != nil {
				fmt.Fprintf(os.Stderr, "Error: invalid pattern in config: %v\n", err)
				os.Exit(2)
			}
		}
		if *sanitizePolicy != "" {
			data, err := os.ReadFile(*sanitizePolicy)
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
	}

	cmd := exec.CommandContext(ctx, cmdArgs[0], cmdArgs[1:]...)
	cmd.Env = env

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

func runPassthrough(cmd *exec.Cmd, sanitize bool, s *scanner.Scanner, extraValues []string) {
	if sanitize {
		var stdoutBuf, stderrBuf bytes.Buffer
		cmd.Stdout = &stdoutBuf
		cmd.Stderr = &stderrBuf
		if err := cmd.Run(); err != nil {
			var exitErr *exec.ExitError
			if errors.As(err, &exitErr) {
				os.Stdout.Write(s.ScanWithValues(stdoutBuf.Bytes(), extraValues))
				os.Stderr.Write(s.ScanWithValues(stderrBuf.Bytes(), extraValues))
				os.Exit(exitErr.ExitCode())
			}
			os.Stdout.Write(s.ScanWithValues(stdoutBuf.Bytes(), extraValues))
			os.Stderr.Write(s.ScanWithValues(stderrBuf.Bytes(), extraValues))
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		os.Stdout.Write(s.ScanWithValues(stdoutBuf.Bytes(), extraValues))
		os.Stderr.Write(s.ScanWithValues(stderrBuf.Bytes(), extraValues))
		return
	}
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			os.Exit(exitErr.ExitCode())
		}
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
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
