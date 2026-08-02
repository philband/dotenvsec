package app

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"strings"

	"github.com/philband/dotenvsec/internal/config"
	"github.com/philband/dotenvsec/internal/identity"
	localprovider "github.com/philband/dotenvsec/internal/provider"
)

func PrepareSOPSIdentities(ctx context.Context, prepared *Prepared) (string, func(), error) {
	var allowed []string
	for _, recipient := range prepared.Manifest.Recipients {
		if recipient.Status == "active" && recipient.Plugin == "yubikey" {
			allowed = append(allowed, recipient.Recipient)
		}
	}
	configured := ""
	if len(prepared.Settings.IdentityPaths) == 1 {
		configured = prepared.Settings.IdentityPaths[0]
	}
	result, err := identity.PrepareConnectedYubiKeys(ctx, configured, prepared.Provider.PluginPath, allowed)
	if err != nil {
		return "", nil, err
	}
	cleanup := result.Cleanup
	if result.PersistentPath != "" && (len(prepared.Settings.IdentityPaths) != 1 || prepared.Settings.IdentityPaths[0] != result.PersistentPath) {
		prepared.Settings.IdentityPaths = []string{result.PersistentPath}
		result.Changed = true
	}
	if result.Changed {
		if err := config.SaveSettings(prepared.Settings); err != nil {
			cleanup()
			return "", nil, err
		}
		sourceHash, err := localprovider.FileSHA256(prepared.Source)
		if err != nil {
			cleanup()
			return "", nil, err
		}
		identityHash := sha256.Sum256([]byte(strings.Join(prepared.Settings.IdentityPaths, "\x00")))
		prepared.CacheKey = prepared.TrustHash + ":" + sourceHash + ":" + prepared.Provider.SHA256 + ":" + hex.EncodeToString(identityHash[:])
	}
	return result.EffectivePath, cleanup, nil
}
