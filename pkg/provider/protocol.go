// Package provider defines the versioned one-shot provider protocol.
package provider

const (
	ProtocolVersion = 2
	MaxMessageBytes = 1 << 20
)

// Tool is an external executable the provider may launch, resolved by the
// parent from its local registry. Repository configuration can never name one:
// Config carries policy only, and the parent overwrites Tools before dispatch.
type Tool struct {
	Executable string `json:"executable"`
	SHA256     string `json:"sha256"`
}

type Scope struct {
	RepositoryID string `json:"repository_id"`
	RelativePath string `json:"relative_path"`
	WorktreeRoot string `json:"worktree_root"`
}

type Request struct {
	Version       int               `json:"version"`
	Scope         Scope             `json:"scope"`
	Source        string            `json:"source"`
	ExpectedNames []string          `json:"expected_names"`
	Unset         []string          `json:"unset,omitempty"`
	Config        map[string]string `json:"config,omitempty"`
	Tools         map[string]Tool   `json:"tools,omitempty"`
	IdentityPath  string            `json:"identity_path,omitempty"`
}

type Error struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

type Response struct {
	Version     int               `json:"version"`
	Environment map[string]string `json:"environment,omitempty"`
	Unset       []string          `json:"unset,omitempty"`
	Error       *Error            `json:"error,omitempty"`
}
