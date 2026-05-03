package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"

	"xmr-ops/internal/audit"
	"xmr-ops/internal/output"
	"xmr-ops/internal/serve"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "usage: xmr-ops audit|serve")
		return 3
	}

	switch args[0] {
	case "audit":
		return runAudit(args[1:], stdout, stderr)
	case "serve":
		return runServe(args[1:], stdout, stderr)
	default:
		fmt.Fprintf(stderr, "unknown command: %s\n", args[0])
		return 3
	}
}

func runAudit(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("audit", flag.ContinueOnError)
	fs.SetOutput(io.Discard)

	opts := audit.Options{}
	fs.StringVar(&opts.Root, "root", "", "root")
	fs.StringVar(&opts.Compose, "compose", "", "compose")
	fs.StringVar(&opts.WalletDir, "wallet-dir", "", "wallet-dir")
	fs.StringVar(&opts.Env, "env", "", "env")
	fs.BoolVar(&opts.JSONOutput, "json", false, "json")
	fs.BoolVar(&opts.NoColor, "no-color", false, "no-color")
	fs.BoolVar(&opts.Strict, "strict", false, "strict")

	if err := fs.Parse(args); err != nil || fs.NArg() != 0 {
		if err == nil {
			err = fmt.Errorf("unexpected argument: %s", fs.Arg(0))
		}
		fmt.Fprintf(stderr, "invalid usage: %v\n", err)
		return 3
	}

	report, err := audit.Run(context.Background(), opts)
	if err != nil {
		fmt.Fprintf(stderr, "audit failed: %v\n", err)
		return 3
	}

	if opts.JSONOutput {
		if err := output.WriteJSON(stdout, report); err != nil {
			fmt.Fprintf(stderr, "write failed: %v\n", err)
			return 3
		}
	} else {
		if err := output.WriteText(stdout, report, opts.NoColor); err != nil {
			fmt.Fprintf(stderr, "write failed: %v\n", err)
			return 3
		}
	}

	return output.ExitCode(report, opts.Strict)
}

func runServe(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	fs.SetOutput(io.Discard)

	auditOpts := audit.Options{}
	serveOpts := serve.Options{Addr: serve.DefaultAddr}
	fs.StringVar(&auditOpts.Root, "root", "", "root")
	fs.StringVar(&serveOpts.Addr, "addr", serve.DefaultAddr, "addr")
	fs.StringVar(&auditOpts.Compose, "compose", "", "compose")
	fs.StringVar(&auditOpts.WalletDir, "wallet-dir", "", "wallet-dir")
	fs.StringVar(&auditOpts.Env, "env", "", "env")
	fs.BoolVar(&serveOpts.UnsafePublicBind, "unsafe-public-bind", false, "unsafe-public-bind")

	if err := fs.Parse(args); err != nil || fs.NArg() != 0 {
		if err == nil {
			err = fmt.Errorf("unexpected argument: %s", fs.Arg(0))
		}
		fmt.Fprintf(stderr, "invalid usage: %v\n", err)
		return 3
	}

	serveOpts.Audit = auditOpts
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	if err := serve.Run(ctx, serveOpts, stdout); err != nil {
		fmt.Fprintf(stderr, "serve failed: %v\n", err)
		return 3
	}
	return 0
}
