package cli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"syscall"

	"github.com/philband/dotenvsec/internal/agent"
	"github.com/philband/dotenvsec/internal/app"
	"github.com/philband/dotenvsec/internal/config"
	"github.com/philband/dotenvsec/internal/environment"
	"github.com/philband/dotenvsec/internal/provider"
	"github.com/spf13/cobra"
)

var version = "dev"

func Execute() error { return newRoot().Execute() }

func newRoot() *cobra.Command {
	root := &cobra.Command{Use: "dotenvsec", Short: "Fail-closed SOPS environment loading", SilenceUsage: true, SilenceErrors: true}
	root.Version = version
	root.AddCommand(newAllow(), newStatus(), newDoctor(), newHook(), newActivate(), newExec(), newShell(), newProvider(), newAgent(), newInit(), newEdit(), newRekey())
	return root
}

func pathArg(args []string) string {
	if len(args) > 0 {
		return args[0]
	}
	cwd, _ := os.Getwd()
	return cwd
}

func newAllow() *cobra.Command {
	var dangerous []string
	cmd := &cobra.Command{Use: "allow [path]", Args: cobra.MaximumNArgs(1), Short: "Approve the selected scope policy locally", RunE: func(_ *cobra.Command, args []string) error {
		hash, err := app.Approve(pathArg(args), dangerous)
		if err != nil {
			return err
		}
		fmt.Printf("approved scope policy %s\n", hash)
		return nil
	}}
	cmd.Flags().StringSliceVar(&dangerous, "dangerous", nil, "locally approve named dangerous variables")
	return cmd
}

func newStatus() *cobra.Command {
	var showNames bool
	cmd := &cobra.Command{Use: "status [path]", Args: cobra.MaximumNArgs(1), Short: "Show scope status without decrypting", RunE: func(_ *cobra.Command, args []string) error {
		status, err := app.Inspect(pathArg(args))
		if err != nil {
			return err
		}
		if !status.Configured {
			fmt.Println("scope: none")
			return nil
		}
		fmt.Printf("scope: %s\napproved: %t\nprovider: %s\nsource: %s\ncache ttl: %s\nvariable count: %d\n", displayRoot(status.Scope), status.Approved, status.Provider, status.Source, status.CacheTTL, status.Variables)
		if showNames {
			prepared, err := app.Prepare(pathArg(args), false)
			if err != nil {
				return err
			}
			fmt.Println("variables:", strings.Join(prepared.Config.Environment, ", "))
		}
		return nil
	}}
	cmd.Flags().BoolVar(&showNames, "show-names", false, "show declared variable names")
	return cmd
}

func newDoctor() *cobra.Command {
	return &cobra.Command{Use: "doctor [path]", Args: cobra.MaximumNArgs(1), Short: "Check dependencies, trust, and scope health", RunE: func(_ *cobra.Command, args []string) error {
		path := pathArg(args)
		prepared, err := app.Prepare(path, false)
		if err != nil {
			return err
		}
		checks := []struct {
			name string
			err  error
		}{{"scope and Git boundary", nil}, {"provider checksum", provider.Verify(prepared.Provider)}, {"local approval", approvalError(prepared)}, {"SOPS", executableCheck(prepared.Config.ProviderConfig["sops_executable"])}, {"cache TTL", ttlCheck(prepared)}}
		failed := false
		for _, check := range checks {
			if check.err != nil {
				failed = true
				fmt.Printf("FAIL %-24s %v\n", check.name, check.err)
			} else {
				fmt.Printf("OK   %s\n", check.name)
			}
		}
		if failed {
			return errors.New("one or more health checks failed")
		}
		return nil
	}}
}

func newHook() *cobra.Command {
	return &cobra.Command{Use: "hook <bash|zsh>", Args: cobra.ExactArgs(1), Short: "Print a static shell hook", RunE: func(_ *cobra.Command, args []string) error {
		exe, err := os.Executable()
		if err != nil {
			return err
		}
		hook, err := environment.Hook(args[0], exe)
		if err != nil {
			return err
		}
		fmt.Print(hook)
		return nil
	}}
}

func newActivate() *cobra.Command {
	var shell string
	var current string
	cmd := &cobra.Command{Use: "activate [path]", Hidden: true, Args: cobra.MaximumNArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
		prepared, prepareErr := app.Prepare(pathArg(args), true)
		if prepareErr == nil && current == app.Marker(prepared) {
			return nil
		}
		loaded, err := app.Load(cmd.Context(), pathArg(args))
		if err != nil {
			fmt.Print(environment.ClearScript())
			if !errors.Is(err, os.ErrNotExist) {
				fmt.Fprintln(os.Stderr, "dotenvsec:", err)
			}
			return nil
		}
		defer environment.Zero(loaded.Environment)
		if prepareErr != nil {
			prepared, prepareErr = app.Prepare(pathArg(args), true)
		}
		if prepareErr != nil {
			fmt.Print(environment.ClearScript())
			return prepareErr
		}
		script, err := environment.Transition(shell, app.Marker(prepared), loaded.Environment, loaded.Unset)
		if err != nil {
			fmt.Print(environment.ClearScript())
			return err
		}
		fmt.Print(script)
		return nil
	}}
	cmd.Flags().StringVar(&shell, "shell", "", "target shell")
	cmd.Flags().StringVar(&current, "current", "", "current scope marker")
	return cmd
}

func newExec() *cobra.Command {
	var path string
	cmd := &cobra.Command{Use: "exec [path] -- command [args...]", Args: cobra.MinimumNArgs(1), DisableFlagParsing: true, Short: "Run one command with the selected environment", RunE: func(cmd *cobra.Command, args []string) error {
		if path == "" && len(args) > 1 {
			if info, err := os.Stat(args[0]); err == nil && info.IsDir() {
				path, args = args[0], args[1:]
			}
		}
		if path == "" {
			path, _ = os.Getwd()
		}
		loaded, err := app.Load(cmd.Context(), path)
		if err != nil {
			return err
		}
		defer environment.Zero(loaded.Environment)
		executable, err := exec.LookPath(args[0])
		if err != nil {
			return err
		}
		return syscall.Exec(executable, args, app.Environment(os.Environ(), loaded))
	}}
	return cmd
}

func newShell() *cobra.Command {
	return &cobra.Command{Use: "shell [path]", Args: cobra.MaximumNArgs(1), Short: "Start an isolated shell with the selected environment", RunE: func(cmd *cobra.Command, args []string) error {
		loaded, err := app.Load(cmd.Context(), pathArg(args))
		if err != nil {
			return err
		}
		defer environment.Zero(loaded.Environment)
		shell := os.Getenv("SHELL")
		if shell == "" {
			shell = "/bin/sh"
		}
		child := exec.CommandContext(cmd.Context(), shell, "-i")
		child.Stdin, child.Stdout, child.Stderr = os.Stdin, os.Stdout, os.Stderr
		child.Env = app.Environment(os.Environ(), loaded)
		return child.Run()
	}}
}

func newProvider() *cobra.Command {
	root := &cobra.Command{Use: "provider", Short: "Manage the local provider registry"}
	var checksum string
	register := &cobra.Command{Use: "register <id> <absolute-executable>", Args: cobra.ExactArgs(2), RunE: func(_ *cobra.Command, args []string) error {
		hash, err := app.RegisterProvider(args[0], args[1], checksum)
		if err == nil {
			fmt.Println(hash)
		}
		return err
	}}
	register.Flags().StringVar(&checksum, "sha256", "", "expected SHA-256 (recommended)")
	root.AddCommand(register, &cobra.Command{Use: "revoke <id>", Args: cobra.ExactArgs(1), RunE: func(_ *cobra.Command, args []string) error { return app.RevokeProvider(args[0]) }}, &cobra.Command{Use: "list", Args: cobra.NoArgs, RunE: func(_ *cobra.Command, _ []string) error {
		settings, err := config.LoadSettings()
		if err != nil {
			return err
		}
		ids := make([]string, 0, len(settings.Providers))
		for id := range settings.Providers {
			ids = append(ids, id)
		}
		sort.Strings(ids)
		for _, id := range ids {
			item := settings.Providers[id]
			state := "ok"
			if err := provider.Verify(item); err != nil {
				state = "invalid: " + err.Error()
			}
			fmt.Printf("%s\t%s\t%s\n", id, item.Executable, state)
		}
		return nil
	}})
	return root
}

func newAgent() *cobra.Command {
	root := &cobra.Command{Use: "agent", Short: "Manage the optional memory-only cache agent"}
	root.AddCommand(
		&cobra.Command{Use: "serve", Args: cobra.NoArgs, Short: "Run the private per-user agent", RunE: func(_ *cobra.Command, _ []string) error { return agent.Serve() }},
		&cobra.Command{Use: "flush", Args: cobra.NoArgs, Short: "Remove every cached entry", RunE: func(_ *cobra.Command, _ []string) error {
			_, _, _, err := agent.Client("flush", "", nil, nil, 0)
			return err
		}},
		&cobra.Command{Use: "lock", Args: cobra.NoArgs, Short: "Flush and reject caching until restart", RunE: func(_ *cobra.Command, _ []string) error {
			_, _, _, err := agent.Client("lock", "", nil, nil, 0)
			return err
		}},
	)
	return root
}

func approvalError(prepared app.Prepared) error {
	approval, ok := prepared.Settings.Approvals[prepared.ScopeKey]
	if !ok || approval.Hash != prepared.TrustHash {
		return errors.New("not approved")
	}
	return nil
}
func executableCheck(path string) error {
	if path == "" {
		_, err := exec.LookPath("sops")
		return err
	}
	if !filepath.IsAbs(path) {
		return errors.New("SOPS executable is not absolute")
	}
	_, err := os.Stat(path)
	return err
}
func ttlCheck(prepared app.Prepared) error {
	ttl, maximum := prepared.Config.CacheTTL.Duration, prepared.Settings.MaximumCacheTTL.Duration
	if ttl < 0 || (maximum > 0 && ttl > maximum) {
		return errors.New("repository TTL exceeds user maximum")
	}
	return nil
}
func displayRoot(path string) string {
	if path == "" {
		return "."
	}
	return path
}

func runAttached(ctx context.Context, executable string, args ...string) error {
	command := exec.CommandContext(ctx, executable, args...)
	command.Stdin, command.Stdout, command.Stderr = os.Stdin, os.Stdout, os.Stderr
	command.Env = stableLocaleEnvironment(os.Environ())
	return command.Run()
}

func stableLocaleEnvironment(base []string) []string {
	out := make([]string, 0, len(base)+2)
	for _, item := range base {
		if strings.HasPrefix(item, "LANG=") || strings.HasPrefix(item, "LC_ALL=") {
			continue
		}
		out = append(out, item)
	}
	return append(out, "LANG=C", "LC_ALL=C")
}
func defaultSOPS() string {
	if runtime.GOOS == "darwin" {
		if _, err := os.Stat("/opt/homebrew/bin/sops"); err == nil {
			return "/opt/homebrew/bin/sops"
		}
	}
	path, _ := exec.LookPath("sops")
	return path
}
