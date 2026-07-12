package cli

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
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
	var owner, plugin, sopsPath string
	cmd := &cobra.Command{Use: "init [path]", Aliases: []string{"i"}, Args: cobra.MaximumNArgs(1), Short: "Initialize an encrypted environment scope", RunE: func(cmd *cobra.Command, args []string) error {
		dir := pathArg(args)
		absolute, err := filepath.Abs(dir)
		if err != nil {
			return err
		}
		if len(names) == 0 || len(recipientSpecs) == 0 {
			return errors.New("at least one --name and --recipient are required")
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
		hash, err := provider.FileSHA256(sopsPath)
		if err != nil {
			return err
		}
		pluginPath, err := initPluginPath(plugin, sopsPath)
		if err != nil {
			return err
		}
		scopeConfig := config.Scope{Schema: 1, Provider: "sops", Source: ".env.sops.yaml", Environment: names, ProviderConfig: map[string]string{"sops_executable": sopsPath, "sops_sha256": hash, "plugin_path": pluginPath}}
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
		if err := installInitFiles(recipientsDir, []initFile{
			{recipientsPath, manifestData, 0644},
			{sopsConfigPath, sopsConfig, 0644},
			{scopeConfigPath, scopeData, 0644},
			{environmentPath, encrypted, 0644},
		}); err != nil {
			return err
		}
		fmt.Println("scope initialized; review and git add all four files, then run dotenvsec allow")
		return nil
	}}
	cmd.Flags().StringSliceVarP(&names, "name", "n", nil, "expected environment variable (repeatable or comma-separated)")
	cmd.Flags().StringSliceVarP(&recipientSpecs, "recipient", "r", nil, "recipient as ID=PUBLIC_RECIPIENT (repeatable)")
	cmd.Flags().StringVarP(&owner, "owner", "o", os.Getenv("USER"), "recipient owner")
	cmd.Flags().StringVarP(&plugin, "plugin", "p", "age", "age, yubikey, or secure-enclave")
	cmd.Flags().StringVarP(&sopsPath, "sops", "s", "", "absolute SOPS executable")
	return cmd
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

func newEdit() *cobra.Command {
	return &cobra.Command{Use: "edit [path]", Args: cobra.MaximumNArgs(1), Short: "Edit the encrypted scope with SOPS", RunE: func(cmd *cobra.Command, args []string) error {
		prepared, err := app.Prepare(pathArg(args), true)
		if err != nil {
			return err
		}
		sopsPath := prepared.Config.ProviderConfig["sops_executable"]
		if err := verifySOPS(prepared); err != nil {
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
		var recipients []string
		for _, item := range prepared.Manifest.Recipients {
			if item.Status == "active" {
				recipients = append(recipients, item.Recipient)
			}
		}
		if len(recipients) == 0 {
			return errors.New("manifest has no active recipients")
		}
		sopsPath := prepared.Config.ProviderConfig["sops_executable"]
		if err := verifySOPS(prepared); err != nil {
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
		encrypt := exec.CommandContext(cmd.Context(), sopsPath, "encrypt", "--input-type", "yaml", "--output-type", "yaml", "--age", strings.Join(recipients, ","), "/dev/stdin")
		encrypt.Dir = prepared.Identity.Directory
		encrypt.Stdin = bytes.NewReader(plain)
		encrypt.Stderr = os.Stderr
		encrypt.Env = stableLocaleEnvironment(os.Environ())
		replacement, err := encrypt.Output()
		if err != nil {
			return errors.New("cannot encrypt replacement")
		}
		tmp, err := writeTemp(filepath.Dir(prepared.Source), replacement, 0644)
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

func verifySOPS(prepared app.Prepared) error {
	path, expected := prepared.Config.ProviderConfig["sops_executable"], prepared.Config.ProviderConfig["sops_sha256"]
	if !filepath.IsAbs(path) || expected == "" {
		return errors.New("absolute checksum-pinned SOPS executable is required")
	}
	actual, err := provider.FileSHA256(path)
	if err != nil {
		return err
	}
	if !strings.EqualFold(actual, expected) {
		return errors.New("sops checksum mismatch")
	}
	return nil
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
