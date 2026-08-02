package cli

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"unicode"

	"github.com/philband/dotenvsec/internal/app"
	"github.com/philband/dotenvsec/internal/config"
	"github.com/philband/dotenvsec/internal/provider"
	"github.com/philband/dotenvsec/internal/recipients"
	"github.com/philband/dotenvsec/internal/scope"
	"github.com/spf13/cobra"
)

func newInit() *cobra.Command {
	var names []string
	var recipientSpecs []string
	var owner, plugin, sopsPath, minVersion string
	var local, gitLocal bool
	cmd := &cobra.Command{Use: "init [path]", Aliases: []string{"i"}, Args: cobra.MaximumNArgs(1), Short: "Initialize an encrypted environment scope", RunE: func(cmd *cobra.Command, args []string) error {
		dir := pathArg(args)
		absolute, err := filepath.Abs(dir)
		if err != nil {
			return err
		}
		absolute, err = filepath.EvalSymlinks(absolute)
		if err != nil {
			return err
		}
		if len(names) == 0 || len(recipientSpecs) == 0 {
			return errors.New("at least one --name and --recipient are required")
		}
		if local && gitLocal {
			return errors.New("--local and --git-local are mutually exclusive")
		}
		mode := config.ScopeModeRepository
		if local {
			mode = config.ScopeModeLocal
		}
		if gitLocal {
			mode = config.ScopeModeGitLocal
		}
		gitContext, gitErr := scope.InspectGit(absolute)
		switch mode {
		case config.ScopeModeRepository:
			if gitErr != nil {
				return errors.New("repository mode requires a Git worktree; use --local for an untracked scope")
			}
		case config.ScopeModeGitLocal:
			if gitErr != nil {
				return errors.New("git-local mode requires a Git worktree")
			}
			if gitContext.LinkedWorktree {
				return errors.New("git-local scopes can only be initialized from the main worktree")
			}
		}
		if err := validateInitPlugin(plugin); err != nil {
			return err
		}
		manifestRecipients, encryptionRecipients, err := parseInitRecipients(recipientSpecs, owner, plugin)
		if err != nil {
			return err
		}
		if sopsPath == "" {
			sopsPath = defaultSOPS()
		}
		if sopsPath == "" {
			return errors.New("sops not found")
		}
		recipientsDir := filepath.Join(absolute, ".dotenv-sec")
		recipientsPath := filepath.Join(recipientsDir, "recipients.yaml")
		sopsConfigPath := filepath.Join(absolute, ".sops.yaml")
		scopeConfigPath := filepath.Join(absolute, scope.ConfigName)
		environmentPath := filepath.Join(absolute, ".env.sops.yaml")
		for _, target := range []string{recipientsDir, sopsConfigPath, scopeConfigPath, environmentPath} {
			if _, err := os.Stat(target); err == nil {
				return fmt.Errorf("refusing to overwrite %s; remove only confirmed partial init output before retrying", target)
			} else if !errors.Is(err, os.ErrNotExist) {
				return err
			}
		}
		manifest := config.RecipientManifest{Schema: 1, Recipients: manifestRecipients}
		if err := config.ValidateRecipients(manifest); err != nil {
			return err
		}
		manifestData, _ := config.Marshal(manifest)
		sopsConfig, err := recipients.GenerateSOPS(manifest, ".env.sops.yaml")
		if err != nil {
			return err
		}
		pluginPath, err := initPluginPath(plugin, sopsPath)
		if err != nil {
			return err
		}
		// Bind the executable in the local registry before writing any scope file,
		// so a machine that cannot be bound never gets a scope it cannot load.
		if _, err := bindTool("sops", "sops", sopsPath, pluginPath); err != nil {
			return err
		}
		scopeMode := ""
		if mode != config.ScopeModeRepository {
			scopeMode = mode
		}
		providerConfig := map[string]string{}
		if minVersion != "" {
			providerConfig["sops_min_version"] = minVersion
		}
		scopeConfig := config.Scope{Schema: config.ScopeSchemaVersion, Mode: scopeMode, Provider: "sops", Source: ".env.sops.yaml", Environment: names, ProviderConfig: providerConfig}
		if err := config.ValidateScope(scopeConfig); err != nil {
			return err
		}
		scopeData, _ := config.Marshal(scopeConfig)
		doc := config.EnvironmentDocument{Environment: map[string]string{}}
		for _, name := range names {
			doc.Environment[name] = "CHANGE_ME"
		}
		plain, _ := config.Marshal(doc)
		defer zeroBytes(plain)
		stagingDir, err := os.MkdirTemp(absolute, ".dotenv-sec-init-*")
		if err != nil {
			return err
		}
		defer func() { _ = os.RemoveAll(stagingDir) }()
		stagedSOPSConfig := filepath.Join(stagingDir, ".sops.yaml")
		if err := os.WriteFile(stagedSOPSConfig, sopsConfig, 0600); err != nil {
			return err
		}
		command := exec.CommandContext(cmd.Context(), sopsPath, "--config", stagedSOPSConfig, "encrypt", "--filename-override", ".env.sops.yaml", "--input-type", "yaml", "--output-type", "yaml", "--age", strings.Join(encryptionRecipients, ","), "/dev/stdin")
		command.Dir = absolute
		command.Stdin = bytes.NewReader(plain)
		command.Env = stableLocaleEnvironment(os.Environ())
		var sopsError bytes.Buffer
		command.Stderr = &sopsError
		encrypted, err := command.Output()
		if err != nil {
			message := strings.TrimSpace(sopsError.String())
			if message == "" {
				return fmt.Errorf("sops encryption failed: %w", err)
			}
			return fmt.Errorf("sops encryption failed: %s", message)
		}
		fileMode := os.FileMode(0644)
		if mode != config.ScopeModeRepository {
			fileMode = 0600
			if gitErr == nil {
				if err := scope.EnsureLocalIgnored(absolute); err != nil {
					return err
				}
			}
		}
		files := []initFile{
			{recipientsPath, manifestData, fileMode},
			{sopsConfigPath, sopsConfig, fileMode},
			{scopeConfigPath, scopeData, fileMode},
			{environmentPath, encrypted, fileMode},
		}
		if err := installInitFiles(recipientsDir, files); err != nil {
			return err
		}
		if mode == config.ScopeModeGitLocal {
			if err := scope.RegisterGitLocal(absolute); err != nil {
				removeInitFiles(recipientsDir, files)
				return err
			}
		}
		switch mode {
		case config.ScopeModeRepository:
			fmt.Println("repository scope initialized; review and git add all four files, then run dotenvsec allow")
		case config.ScopeModeLocal:
			fmt.Println("local scope initialized; files are private and untracked; review them, then run dotenvsec allow")
		case config.ScopeModeGitLocal:
			fmt.Println("git-local scope initialized; linked worktrees inherit it read-only; review it, then run dotenvsec allow")
		}
		return nil
	}}
	cmd.Flags().StringSliceVarP(&names, "name", "n", nil, "expected environment variable (repeatable or comma-separated)")
	cmd.Flags().StringSliceVarP(&recipientSpecs, "recipient", "r", nil, "recipient as ID=PUBLIC_RECIPIENT (repeatable)")
	cmd.Flags().StringVarP(&owner, "owner", "o", os.Getenv("USER"), "recipient owner")
	cmd.Flags().StringVarP(&plugin, "plugin", "p", "age", "age, yubikey, or secure-enclave")
	cmd.Flags().StringVarP(&sopsPath, "sops", "s", "", "absolute SOPS executable to bind in the local registry")
	cmd.Flags().StringVar(&minVersion, "sops-min-version", "", "minimum SOPS version this scope requires, for example 3.10.0")
	cmd.Flags().BoolVar(&local, "local", false, "create a private untracked scope that belongs only to this directory tree")
	cmd.Flags().BoolVar(&gitLocal, "git-local", false, "create a private main-worktree scope inherited read-only by linked worktrees")
	return cmd
}

// bindTool pins an external executable for a locally registered provider. This
// is per-user state: the checksum is recorded here rather than in a tracked
// scope file, so upgrading the tool is a local action with no cross-machine
// effect. An empty pluginPath leaves any existing search path untouched.
func bindTool(providerID, tool, executable, pluginPath string) (string, error) {
	absolute, err := filepath.Abs(executable)
	if err != nil {
		return "", err
	}
	// Canonicalize: Homebrew and similar managers expose every binary as a
	// symlink into a versioned directory. Storing the resolved target keeps the
	// checksummed file and the executed file identical.
	absolute, err = provider.ResolveExecutable(absolute)
	if err != nil {
		return "", err
	}
	hash, err := provider.FileSHA256(absolute)
	if err != nil {
		return "", err
	}
	settings, err := config.LoadSettings()
	if err != nil {
		return "", err
	}
	entry, registered := settings.Providers[providerID]
	if !registered {
		return "", fmt.Errorf("provider %q is not registered locally; run dotenvsec provider register %s <absolute-executable> first", providerID, providerID)
	}
	if entry.Tools == nil {
		entry.Tools = map[string]config.ToolEntry{}
	}
	entry.Tools[tool] = config.ToolEntry{Executable: absolute, SHA256: hash}
	if pluginPath != "" {
		entry.PluginPath = pluginPath
	}
	settings.Providers[providerID] = entry
	if err := config.SaveSettings(settings); err != nil {
		return "", err
	}
	return absolute, nil
}

func newMigrate() *cobra.Command {
	return &cobra.Command{Use: "migrate [path]", Args: cobra.MaximumNArgs(1), Short: "Move machine-local provider config out of a schema 1 scope file", RunE: func(_ *cobra.Command, args []string) error {
		directory, err := filepath.Abs(pathArg(args))
		if err != nil {
			return err
		}
		scopePath := filepath.Join(directory, scope.ConfigName)
		data, err := os.ReadFile(scopePath)
		if err != nil {
			return err
		}
		var legacy struct {
			Schema         int               `yaml:"schema"`
			Mode           string            `yaml:"mode,omitempty"`
			Provider       string            `yaml:"provider"`
			Source         string            `yaml:"source"`
			Environment    []string          `yaml:"environment"`
			Unset          []string          `yaml:"unset,omitempty"`
			AllowDangerous []string          `yaml:"allow_dangerous,omitempty"`
			CacheTTL       config.Duration   `yaml:"cache_ttl,omitempty"`
			ProviderConfig map[string]string `yaml:"provider_config,omitempty"`
		}
		if err := config.DecodeStrict(data, &legacy); err != nil {
			return err
		}
		if legacy.Schema == config.ScopeSchemaVersion {
			return errors.New("scope is already at the current schema")
		}
		if legacy.Schema != 1 {
			return fmt.Errorf("cannot migrate scope schema %d", legacy.Schema)
		}
		sopsPath := legacy.ProviderConfig["sops_executable"]
		if sopsPath == "" {
			return errors.New("scope has no sops_executable to migrate; bind it with dotenvsec provider retool")
		}
		if _, err := bindTool(legacy.Provider, "sops", sopsPath, legacy.ProviderConfig["plugin_path"]); err != nil {
			return err
		}
		migrated := config.Scope{Schema: config.ScopeSchemaVersion, Mode: legacy.Mode, Provider: legacy.Provider, Source: legacy.Source, Environment: legacy.Environment, Unset: legacy.Unset, AllowDangerous: legacy.AllowDangerous, CacheTTL: legacy.CacheTTL, ProviderConfig: map[string]string{}}
		for key, value := range legacy.ProviderConfig {
			if !slices.Contains(config.MachineLocalProviderKeys, key) {
				migrated.ProviderConfig[key] = value
			}
		}
		if err := config.ValidateScope(migrated); err != nil {
			return err
		}
		encoded, err := config.Marshal(migrated)
		if err != nil {
			return err
		}
		info, err := os.Stat(scopePath)
		if err != nil {
			return err
		}
		if err := atomicWrite(scopePath, encoded, info.Mode().Perm()); err != nil {
			return err
		}
		fmt.Printf("migrated %s to schema %d; sops is now bound locally\n", scopePath, config.ScopeSchemaVersion)
		fmt.Println("review the scope diff, commit it in repository mode, then run dotenvsec allow on every machine")
		return nil
	}}
}

var recipientIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)

func parseInitRecipients(specs []string, owner, plugin string) ([]config.Recipient, []string, error) {
	manifest := make([]config.Recipient, 0, len(specs))
	encryption := make([]string, 0, len(specs))
	ids, recipients := map[string]struct{}{}, map[string]struct{}{}
	for _, spec := range specs {
		id, recipient, found := strings.Cut(spec, "=")
		if !found || !recipientIDPattern.MatchString(id) || recipient == "" {
			return nil, nil, fmt.Errorf("invalid --recipient %q; expected ID=PUBLIC_RECIPIENT", spec)
		}
		if strings.IndexFunc(recipient, unicode.IsControl) >= 0 {
			return nil, nil, fmt.Errorf("recipient %q contains a control character", id)
		}
		if _, duplicate := ids[id]; duplicate {
			return nil, nil, fmt.Errorf("duplicate recipient ID %q", id)
		}
		if _, duplicate := recipients[recipient]; duplicate {
			return nil, nil, fmt.Errorf("duplicate public recipient for %q", id)
		}
		ids[id], recipients[recipient] = struct{}{}, struct{}{}
		manifest = append(manifest, config.Recipient{ID: id, Owner: owner, Status: "active", Plugin: plugin, Recipient: recipient, Policy: defaultPolicy(plugin), Attestation: "operator supplied public recipient"})
		encryption = append(encryption, recipient)
	}
	return manifest, encryption, nil
}

func validateInitPlugin(plugin string) error {
	switch plugin {
	case "age", "yubikey", "secure-enclave":
		return nil
	default:
		return fmt.Errorf("unsupported recipient plugin %q", plugin)
	}
}

func initPluginPath(plugin, sopsPath string) (string, error) {
	sopsDirectory := filepath.Dir(sopsPath)
	var executable string
	switch plugin {
	case "age":
		return sopsDirectory, nil
	case "yubikey":
		executable = "age-plugin-yubikey"
	case "secure-enclave":
		executable = "age-plugin-se"
	default:
		return "", fmt.Errorf("unsupported recipient plugin %q", plugin)
	}
	pluginExecutable, err := exec.LookPath(executable)
	if err != nil {
		return "", fmt.Errorf("required %s executable not found in PATH", executable)
	}
	pluginDirectory := filepath.Dir(pluginExecutable)
	if pluginDirectory == sopsDirectory {
		return sopsDirectory, nil
	}
	return strings.Join([]string{pluginDirectory, sopsDirectory}, string(os.PathListSeparator)), nil
}

type initFile struct {
	path string
	data []byte
	mode os.FileMode
}

func installInitFiles(recipientsDir string, files []initFile) (err error) {
	if err := os.Mkdir(recipientsDir, 0700); err != nil {
		return err
	}
	installed := make([]string, 0, len(files))
	defer func() {
		if err == nil {
			return
		}
		for _, path := range installed {
			_ = os.Remove(path)
		}
		_ = os.Remove(recipientsDir)
	}()
	for _, file := range files {
		if err = atomicWrite(file.path, file.data, file.mode); err != nil {
			return err
		}
		installed = append(installed, file.path)
	}
	return nil
}

func removeInitFiles(recipientsDir string, files []initFile) {
	for _, file := range files {
		_ = os.Remove(file.path)
	}
	_ = os.Remove(recipientsDir)
}

func newEdit() *cobra.Command {
	return &cobra.Command{Use: "edit [path]", Args: cobra.MaximumNArgs(1), Short: "Edit the encrypted scope with SOPS", RunE: func(cmd *cobra.Command, args []string) error {
		prepared, err := app.Prepare(pathArg(args), true)
		if err != nil {
			return err
		}
		if err := app.EnsureWritable(prepared); err != nil {
			return err
		}
		sopsPath, err := resolveSOPS(cmd.Context(), prepared)
		if err != nil {
			return err
		}
		identityPath, cleanupIdentities, err := app.PrepareSOPSIdentities(cmd.Context(), &prepared)
		if err != nil {
			return err
		}
		defer cleanupIdentities()
		var identityPaths []string
		if identityPath != "" {
			identityPaths = []string{identityPath}
		}
		return runAttached(cmd.Context(), sopsPath, identityPaths, prepared.Settings.Editor, prepared.Source)
	}}
}

func newRekey() *cobra.Command {
	return &cobra.Command{Use: "rekey [path]", Args: cobra.MaximumNArgs(1), Short: "Atomically re-encrypt to active manifest recipients", RunE: func(cmd *cobra.Command, args []string) error {
		prepared, err := app.Prepare(pathArg(args), true)
		if err != nil {
			return err
		}
		if err := app.EnsureWritable(prepared); err != nil {
			return err
		}
		var recipients []string
		for _, item := range prepared.Manifest.Recipients {
			if item.Status == "active" {
				recipients = append(recipients, item.Recipient)
			}
		}
		if len(recipients) == 0 {
			return errors.New("manifest has no active recipients")
		}
		sopsPath, err := resolveSOPS(cmd.Context(), prepared)
		if err != nil {
			return err
		}
		identityPath, cleanupIdentities, err := app.PrepareSOPSIdentities(cmd.Context(), &prepared)
		if err != nil {
			return err
		}
		defer cleanupIdentities()
		var identityPaths []string
		if identityPath != "" {
			identityPaths = []string{identityPath}
		}
		decrypt := exec.CommandContext(cmd.Context(), sopsPath, "decrypt", "--input-type", "yaml", "--output-type", "yaml", prepared.Source)
		decrypt.Stderr = os.Stderr
		decrypt.Env = sopsEnvironment(os.Environ(), identityPaths, "")
		plain, err := decrypt.Output()
		if err != nil {
			return errors.New("cannot decrypt existing source")
		}
		defer zeroBytes(plain)
		encrypt := exec.CommandContext(cmd.Context(), sopsPath, "encrypt", "--filename-override", prepared.Config.Source, "--input-type", "yaml", "--output-type", "yaml", "--age", strings.Join(recipients, ","), "/dev/stdin")
		encrypt.Dir = prepared.Identity.Directory
		encrypt.Stdin = bytes.NewReader(plain)
		encrypt.Stderr = os.Stderr
		encrypt.Env = stableLocaleEnvironment(os.Environ())
		replacement, err := encrypt.Output()
		if err != nil {
			return errors.New("cannot encrypt replacement")
		}
		sourceInfo, err := os.Stat(prepared.Source)
		if err != nil {
			return err
		}
		tmp, err := writeTemp(filepath.Dir(prepared.Source), replacement, sourceInfo.Mode().Perm())
		if err != nil {
			return err
		}
		defer func() { _ = os.Remove(tmp) }()
		verify := exec.CommandContext(cmd.Context(), sopsPath, "decrypt", "--input-type", "yaml", "--output-type", "yaml", tmp)
		verify.Stderr = os.Stderr
		verify.Env = sopsEnvironment(os.Environ(), identityPaths, "")
		verified, err := verify.Output()
		zeroBytes(verified)
		if err != nil {
			return errors.New("replacement verification failed")
		}
		if err := os.Rename(tmp, prepared.Source); err != nil {
			return err
		}
		fmt.Printf("rekeyed to %d active recipients\n", len(recipients))
		return nil
	}}
}

// resolveSOPS returns the SOPS executable bound to this provider in the local
// registry, after verifying its pinned checksum and any repository-declared
// version floor. The scope file never names the executable.
func resolveSOPS(ctx context.Context, prepared app.Prepared) (string, error) {
	tool, bound := prepared.Provider.Tools["sops"]
	if !bound {
		return "", fmt.Errorf("provider %q has no sops tool binding; run dotenvsec provider retool %s sops <absolute-executable>", prepared.Config.Provider, prepared.Config.Provider)
	}
	if err := provider.VerifyExecutable("tool sops", tool.Executable, tool.SHA256); err != nil {
		return "", err
	}
	if err := checkSOPSVersion(ctx, tool.Executable, prepared.Config.ProviderConfig["sops_min_version"]); err != nil {
		return "", err
	}
	return tool.Executable, nil
}

var sopsVersionRE = regexp.MustCompile(`([0-9]+)\.([0-9]+)\.([0-9]+)`)

// checkSOPSVersion enforces the optional repository-declared floor. The floor is
// portable policy: it constrains encryption-format compatibility without naming
// a path or a checksum, so one tracked file works on every platform.
func checkSOPSVersion(ctx context.Context, executable, minimum string) error {
	if minimum == "" {
		return nil
	}
	command := exec.CommandContext(ctx, executable, "--version", "--disable-version-check")
	command.Env = stableLocaleEnvironment(nil)
	out, err := command.Output()
	if err != nil {
		return errors.New("cannot determine sops version")
	}
	found := sopsVersionRE.FindStringSubmatch(string(out))
	if found == nil {
		return errors.New("cannot parse sops version")
	}
	older, err := belowFloor(found[1:], minimum)
	if err != nil {
		return err
	}
	if older {
		return fmt.Errorf("scope requires sops %s or newer; bound executable is %s", minimum, found[0])
	}
	return nil
}

// belowFloor compares the parsed version components against the declared floor.
// Unparsable input is an error rather than a silent pass, so a malformed version
// cannot satisfy a floor by accident.
func belowFloor(actual []string, minimum string) (bool, error) {
	for index, part := range strings.Split(minimum, ".") {
		want, err := strconv.Atoi(part)
		if err != nil {
			return false, fmt.Errorf("invalid sops_min_version %q", minimum)
		}
		got := 0
		if index < len(actual) {
			if got, err = strconv.Atoi(actual[index]); err != nil {
				return false, errors.New("cannot parse sops version")
			}
		}
		if got != want {
			return got < want, nil
		}
	}
	return false, nil
}

func defaultPolicy(plugin string) map[string]string {
	switch plugin {
	case "yubikey":
		return map[string]string{"pin": "always", "touch": "always"}
	case "secure-enclave":
		return map[string]string{"access_control": "current-biometry", "binding": "device"}
	default:
		return nil
	}
}
func atomicWrite(path string, data []byte, mode os.FileMode) error {
	tmp, err := writeTemp(filepath.Dir(path), data, mode)
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(tmp) }()
	return os.Rename(tmp, path)
}
func writeTemp(dir string, data []byte, mode os.FileMode) (string, error) {
	file, err := os.CreateTemp(dir, ".dotenv-sec-*")
	if err != nil {
		return "", err
	}
	name := file.Name()
	if err := file.Chmod(mode); err != nil {
		_ = file.Close()
		return "", err
	}
	if _, err := file.Write(data); err != nil {
		_ = file.Close()
		return "", err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return "", err
	}
	if err := file.Close(); err != nil {
		return "", err
	}
	return name, nil
}
func zeroBytes(data []byte) {
	for i := range data {
		data[i] = 0
	}
}
