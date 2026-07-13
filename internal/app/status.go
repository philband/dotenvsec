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
	Mode       string
	Ownership  string
	Owner      string
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
	ownership, owner := "writable", ""
	if prepared.Identity.ReadOnly {
		ownership = "inherited, read-only"
		owner = prepared.Identity.Directory
	}
	return Status{Configured: true, Approved: ok && approval.Hash == prepared.TrustHash, Scope: filepath.ToSlash(prepared.Identity.RelativePath), Mode: prepared.Identity.Mode, Ownership: ownership, Owner: owner, Provider: prepared.Config.Provider, CacheTTL: prepared.Config.CacheTTL.String(), Variables: len(prepared.Config.Environment), Source: fmt.Sprintf("%s (encrypted)", prepared.Config.Source)}, nil
}
