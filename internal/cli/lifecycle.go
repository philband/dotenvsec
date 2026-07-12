package cli

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/philband/dotenvsec/internal/app"
	"github.com/philband/dotenvsec/internal/config"
	"github.com/philband/dotenvsec/internal/provider"
	"github.com/philband/dotenvsec/internal/recipients"
	"github.com/philband/dotenvsec/internal/scope"
	"github.com/spf13/cobra"
)

func newInit() *cobra.Command {
	var names []string
	var recipient, recipientID, owner, plugin, sopsPath string
	cmd := &cobra.Command{Use: "init [path]", Args: cobra.MaximumNArgs(1), Short: "Initialize an encrypted environment scope", RunE: func(cmd *cobra.Command, args []string) error {
		dir := pathArg(args)
		absolute, err := filepath.Abs(dir)
		if err != nil {
			return err
		}
		if len(names) == 0 || recipient == "" {
			return errors.New("at least one --name and --recipient are required")
		}
		if sopsPath == "" {
			sopsPath = defaultSOPS()
		}
		if sopsPath == "" {
			return errors.New("sops not found")
		}
		for _, target := range []string{filepath.Join(absolute, scope.ConfigName), filepath.Join(absolute, ".env.sops.yaml")} {
			if _, err := os.Stat(target); err == nil {
				return fmt.Errorf("refusing to overwrite %s", target)
			}
		}
		manifest := config.RecipientManifest{Schema: 1, Recipients: []config.Recipient{{ID: recipientID, Owner: owner, Status: "active", Plugin: plugin, Recipient: recipient, Policy: defaultPolicy(plugin), Attestation: "operator supplied public recipient"}}}
		if err := os.MkdirAll(filepath.Join(absolute, ".dotenv-sec"), 0700); err != nil {
			return err
		}
		manifestData, _ := config.Marshal(manifest)
		if err := atomicWrite(filepath.Join(absolute, ".dotenv-sec", "recipients.yaml"), manifestData, 0644); err != nil {
			return err
		}
		sopsConfig, err := recipients.GenerateSOPS(manifest, ".env.sops.yaml")
		if err != nil {
			return err
		}
		if err := atomicWrite(filepath.Join(absolute, ".sops.yaml"), []byte(sopsConfig), 0644); err != nil {
			return err
		}
		hash, err := provider.FileSHA256(sopsPath)
		if err != nil {
			return err
		}
		scopeConfig := config.Scope{Schema: 1, Provider: "sops", Source: ".env.sops.yaml", Environment: names, ProviderConfig: map[string]string{"sops_executable": sopsPath, "sops_sha256": hash, "plugin_path": filepath.Dir(sopsPath)}}
		scopeData, _ := config.Marshal(scopeConfig)
		if err := atomicWrite(filepath.Join(absolute, scope.ConfigName), scopeData, 0644); err != nil {
			return err
		}
		doc := config.EnvironmentDocument{Environment: map[string]string{}}
		for _, name := range names {
			doc.Environment[name] = "CHANGE_ME"
		}
		plain, _ := config.Marshal(doc)
		defer zeroBytes(plain)
		command := exec.CommandContext(cmd.Context(), sopsPath, "encrypt", "--input-type", "yaml", "--output-type", "yaml", "--age", recipient, "/dev/stdin")
		command.Dir = absolute
		command.Stdin = bytes.NewReader(plain)
		command.Stderr = os.Stderr
		encrypted, err := command.Output()
		if err != nil {
			return errors.New("sops encryption failed")
		}
		if err := atomicWrite(filepath.Join(absolute, ".env.sops.yaml"), encrypted, 0644); err != nil {
			return err
		}
		fmt.Println("scope initialized; review files, git add them, register provider, then run allow")
		return nil
	}}
	cmd.Flags().StringSliceVar(&names, "name", nil, "expected environment variable (repeatable)")
	cmd.Flags().StringVar(&recipient, "recipient", "", "public age/plugin recipient")
	cmd.Flags().StringVar(&recipientID, "recipient-id", "primary-device", "stable recipient/device ID")
	cmd.Flags().StringVar(&owner, "owner", os.Getenv("USER"), "recipient owner")
	cmd.Flags().StringVar(&plugin, "plugin", "age", "age, yubikey, or secure-enclave")
	cmd.Flags().StringVar(&sopsPath, "sops", "", "absolute SOPS executable")
	return cmd
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
		return runAttached(cmd.Context(), sopsPath, prepared.Source)
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
		decrypt := exec.CommandContext(cmd.Context(), sopsPath, "decrypt", "--input-type", "yaml", "--output-type", "yaml", prepared.Source)
		decrypt.Stderr = os.Stderr
		plain, err := decrypt.Output()
		if err != nil {
			return errors.New("cannot decrypt existing source")
		}
		defer zeroBytes(plain)
		encrypt := exec.CommandContext(cmd.Context(), sopsPath, "encrypt", "--input-type", "yaml", "--output-type", "yaml", "--age", strings.Join(recipients, ","), "/dev/stdin")
		encrypt.Dir = prepared.Identity.Directory
		encrypt.Stdin = bytes.NewReader(plain)
		encrypt.Stderr = os.Stderr
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
