package app

import (
	"fmt"
	"os"
	"path/filepath"
)

type Status struct {
	Configured bool
	Approved   bool
	Scope      string
	Provider   string
	CacheTTL   string
	Variables  int
	Source     string
}

func Inspect(path string) (Status, error) {
	prepared, err := Prepare(path, false)
	if err != nil {
		if os.IsNotExist(err) {
			return Status{}, nil
		}
		return Status{}, err
	}
	approval, ok := prepared.Settings.Approvals[prepared.ScopeKey]
	return Status{true, ok && approval.Hash == prepared.TrustHash, filepath.ToSlash(prepared.Identity.RelativePath), prepared.Config.Provider, prepared.Config.CacheTTL.String(), len(prepared.Config.Environment), fmt.Sprintf("%s (encrypted)", prepared.Config.Source)}, nil
}
