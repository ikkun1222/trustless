package doctor

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/ikkun1222/trustless/internal/config"
)

var (
	green  = ""
	cyan   = ""
	yellow = ""
	red    = ""
	reset  = ""
)

func init() {
	fi, err := os.Stdout.Stat()
	if err == nil && fi.Mode()&os.ModeCharDevice != 0 {
		green = "\033[32m"
		cyan = "\033[36m"
		yellow = "\033[33m"
		red = "\033[31m"
		reset = "\033[0m"
	}
}

type reportGroup struct {
	Name   string
	Checks []CheckResult
}

func Run(args []string) int {
	return runE(args, os.Stdout, os.Stderr)
}

// runE is the writer-injected core of Run so integration tests capture
// output without swapping os.Stdout/os.Stderr globals.
func runE(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("doctor", flag.ExitOnError)
	fix := fs.Bool("fix", false, "Attempt to fix detected issues")
	jsonOut := fs.Bool("json", false, "Output as JSON")
	fs.Parse(args)

	// backend を config から判定（pass 既定）。config 読めない場合は pass 前提のまま
	// チェックを続行（診断は警告でなく実行を優先）。
	backend := "pass"
	if cfg, err := config.Load(config.DefaultConfigPath()); err == nil && cfg.Backend != "" {
		backend = cfg.Backend
	}

	var groups []reportGroup
	if backend == "bitwarden" {
		groups = []reportGroup{
			{
				Name: "BITWARDEN",
				Checks: []CheckResult{
					CheckBitwardenCLI(),
					CheckBitwardenSession(),
				},
			},
			{
				Name: "SECURITY",
				Checks: []CheckResult{
					CheckEnvFiles(),
				},
			},
			{
				Name: "AGENT INTEGRATIONS",
				Checks: []CheckResult{
					CheckAgentIntegration("OpenCode", opencodeConfigPaths(), opencodeDetectFn),
					CheckAgentIntegration("Claude Code", claudeConfigPaths(), claudeDetectFn),
					CheckAgentIntegration("Codex", codexConfigPaths(), codexDetectFn),
					CheckAgentIntegration("Hermes", hermesConfigPaths(), hermesDetectFn),
				},
			},
			{
				Name: "MITM CA",
				Checks: []CheckResult{
					CheckMITMCA(),
				},
			},
		}
	} else {
		groups = []reportGroup{
			{
				Name: "PASS STORE",
				Checks: []CheckResult{
					CheckGPG(),
					CheckPassStore(),
					CheckGPGAgent(),
				},
			},
			{
				Name: "SECURITY",
				Checks: []CheckResult{
					CheckEnvFiles(),
				},
			},
			{
				Name: "AGENT INTEGRATIONS",
				Checks: []CheckResult{
					CheckAgentIntegration("OpenCode", opencodeConfigPaths(), opencodeDetectFn),
					CheckAgentIntegration("Claude Code", claudeConfigPaths(), claudeDetectFn),
					CheckAgentIntegration("Codex", codexConfigPaths(), codexDetectFn),
					CheckAgentIntegration("Hermes", hermesConfigPaths(), hermesDetectFn),
				},
			},
			{
				Name: "MITM CA",
				Checks: []CheckResult{
					CheckMITMCA(),
				},
			},
		}
	}

	var all []CheckResult
	for _, g := range groups {
		all = append(all, g.Checks...)
	}

	// --fix は出力形式より先に適用する: --json --fix でも修正が有効になる。
	if *fix {
		applyFixes(all, stderr)
	}

	if *jsonOut {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		enc.Encode(all)
		return exitCode(all)
	}

	printReport(groups, all, *fix, stdout)
	return exitCode(all)
}

// exitCode fails the gate (1) when any check is an error. Warnings and info
// results are advisory and do not fail. This lets scripts and CI gate on
// `trustless doctor` instead of parsing the report text.
func exitCode(all []CheckResult) int {
	for _, c := range all {
		if c.Status == StatusError {
			return 1
		}
	}
	return 0
}

// applyFixes runs the fix attached to each Error/Warning check. OK/Info
// results are never touched. Checks without a Fix (e.g. agent integrations,
// .env scan) are skipped and counted so --fix never claims to change
// something it cannot. Totals go to stderr.
func applyFixes(all []CheckResult, stderr io.Writer) {
	var applied, skipped int
	for _, c := range all {
		if c.Status != StatusError && c.Status != StatusWarning {
			continue
		}
		if c.Fix == nil {
			skipped++
			continue
		}
		if err := c.Fix(); err != nil {
			fmt.Fprintf(stderr, "Error fixing %s: %v\n", c.Name, err)
		}
		applied++
	}
	fmt.Fprintf(stderr, "doctor --fix: applied %d fix(es), skipped %d without automatic fix\n", applied, skipped)
}

func printReport(groups []reportGroup, all []CheckResult, fix bool, stdout io.Writer) {
	fmt.Fprintf(stdout, "%strustless doctor%s \u2014 system health check\n\n", cyan, reset)

	for _, g := range groups {
		fmt.Fprintf(stdout, "%s%s%s\n", cyan, g.Name, reset)
		for _, c := range g.Checks {
			ch, col := statusDisplay(c.Status)
			fmt.Fprintf(stdout, "  %s%s%s %s\n", col, ch, reset, c.Message)
		}
		fmt.Fprintln(stdout)
	}

	var errCount, warnCount int
	for _, c := range all {
		switch c.Status {
		case StatusError:
			errCount++
		case StatusWarning:
			warnCount++
		}
	}

	if errCount > 0 || warnCount > 0 {
		fmt.Fprintf(stdout, "Summary: %d error(s), %d warning(s).", errCount, warnCount)
		if !fix {
			fmt.Fprint(stdout, " Run with --fix to auto-resolve.\n")
		} else {
			fmt.Fprint(stdout, "\n")
		}
	} else {
		fmt.Fprintf(stdout, "Summary: All checks passed.\n")
	}
}

func statusDisplay(s CheckStatus) (string, string) {
	switch s {
	case StatusOK:
		return "\u2713", green
	case StatusWarning:
		return "!", yellow
	case StatusError:
		return "\u2717", red
	case StatusInfo:
		return "\u26A0", yellow
	default:
		return "?", reset
	}
}
