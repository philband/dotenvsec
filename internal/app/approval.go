package app

import (
	"time"

	"github.com/philband/dotenvsec/internal/config"
)

func Approve(path string, dangerous []string) (string, error) {
	prepared, err := Prepare(path, false)
	if err != nil {
		return "", err
	}
	if err := EnsureWritable(prepared); err != nil {
		return "", err
	}
	prepared.Settings.Approvals[prepared.ScopeKey] = config.Approval{Hash: prepared.TrustHash, ApprovedAt: time.Now().UTC().Format(time.RFC3339)}
	if dangerous != nil {
		prepared.Settings.DangerousApprovals[prepared.ScopeKey] = append([]string(nil), dangerous...)
	}
	if err := config.SaveSettings(prepared.Settings); err != nil {
		return "", err
	}
	return prepared.TrustHash, nil
}
