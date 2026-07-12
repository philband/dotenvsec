package config

import (
	"fmt"
	"time"

	"gopkg.in/yaml.v3"
)

const (
	ScopeSchemaVersion      = 1
	RecipientsSchemaVersion = 1
	SettingsSchemaVersion   = 1
	MaxYAMLBytes            = 1 << 20
	MaxEnvironmentBytes     = 512 << 10
	MaxEnvironmentVariables = 4096
)

type Duration struct{ time.Duration }

func (d *Duration) UnmarshalYAML(node *yaml.Node) error {
	if node.Kind != yaml.ScalarNode || node.Tag != "!!str" {
		return fmt.Errorf("duration must be an explicit string")
	}
	parsed, err := time.ParseDuration(node.Value)
	if err != nil || parsed < 0 {
		return fmt.Errorf("invalid non-negative duration %q", node.Value)
	}
	d.Duration = parsed
	return nil
}

type Scope struct {
	Schema         int               `yaml:"schema"`
	Provider       string            `yaml:"provider"`
	Source         string            `yaml:"source"`
	Environment    []string          `yaml:"environment"`
	Unset          []string          `yaml:"unset,omitempty"`
	AllowDangerous []string          `yaml:"allow_dangerous,omitempty"`
	CacheTTL       Duration          `yaml:"cache_ttl,omitempty"`
	ProviderConfig map[string]string `yaml:"provider_config,omitempty"`
}

type RecipientManifest struct {
	Schema     int         `yaml:"schema"`
	Recipients []Recipient `yaml:"recipients"`
}

type Recipient struct {
	ID          string            `yaml:"id"`
	Owner       string            `yaml:"owner"`
	Status      string            `yaml:"status"`
	Plugin      string            `yaml:"plugin"`
	Recipient   string            `yaml:"recipient"`
	Policy      map[string]string `yaml:"policy,omitempty"`
	Attestation string            `yaml:"attestation,omitempty"`
}

type Settings struct {
	Schema             int                      `yaml:"schema"`
	MaximumCacheTTL    Duration                 `yaml:"maximum_cache_ttl,omitempty"`
	Providers          map[string]ProviderEntry `yaml:"providers,omitempty"`
	Approvals          map[string]Approval      `yaml:"approvals,omitempty"`
	DangerousApprovals map[string][]string      `yaml:"dangerous_approvals,omitempty"`
	IdentityPaths      []string                 `yaml:"identity_paths,omitempty"`
}

type ProviderEntry struct {
	Executable string   `yaml:"executable"`
	SHA256     string   `yaml:"sha256"`
	Timeout    Duration `yaml:"timeout,omitempty"`
}

type Approval struct {
	Hash       string `yaml:"hash"`
	ApprovedAt string `yaml:"approved_at"`
}

type EnvironmentDocument struct {
	Environment map[string]string `yaml:"environment"`
}
