package doctor

import (
	"encoding/json"
	"flag"
	"fmt"
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

	if *jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(all)
		return exitCode(all)
	}

	if *fix {
		applyFixes(all)
	}
	printReport(groups, all, *fix)
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

// applyFixes runs the fix attached to each check that has one. Checks marked
// Fixable without a Fix (agent integrations) are skipped so --fix never
// claims to change something it cannot.
func applyFixes(all []CheckResult) {
	for _, c := range all {
		if c.Fix == nil {
			continue
		}
		if err := c.Fix(); err != nil {
			fmt.Fprintf(os.Stderr, "Error fixing %s: %v\n", c.Name, err)
		}
	}
}

func printReport(groups []reportGroup, all []CheckResult, fix bool) {
	fmt.Printf("%strustless doctor%s \u2014 system health check\n\n", cyan, reset)

	for _, g := range groups {
		fmt.Printf("%s%s%s\n", cyan, g.Name, reset)
		for _, c := range g.Checks {
			ch, col := statusDisplay(c.Status)
			fmt.Printf("  %s%s%s %s\n", col, ch, reset, c.Message)
		}
		fmt.Println()
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
		fmt.Printf("Summary: %d error(s), %d warning(s).", errCount, warnCount)
		if !fix {
			fmt.Print(" Run with --fix to auto-resolve.\n")
		} else {
			fmt.Print("\n")
		}
	} else {
		fmt.Printf("Summary: All checks passed.\n")
	}
}

func statusDisplay(s CheckStatus) (string, string) {
	switch s {
	case StatusOK:
		return "\u2713", green
	case StatusWarning:
		return "\u2717", red
	case StatusError:
		return "\u2717", red
	case StatusInfo:
		return "\u26A0", yellow
	default:
		return "?", reset
	}
}
