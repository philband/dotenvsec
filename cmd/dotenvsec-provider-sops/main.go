package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/philband/dotenvsec/internal/config"
	localprovider "github.com/philband/dotenvsec/internal/provider"
	protocol "github.com/philband/dotenvsec/pkg/provider"
)

func main() {
	if err := run(); err != nil {
		_ = json.NewEncoder(os.Stdout).Encode(protocol.Response{Version: protocol.ProtocolVersion, Error: &protocol.Error{Code: "sops_failed", Message: err.Error()}})
	}
}

func run() error {
	data, err := io.ReadAll(io.LimitReader(os.Stdin, protocol.MaxMessageBytes+1))
	if err != nil {
		return errors.New("cannot read request")
	}
	if len(data) > protocol.MaxMessageBytes {
		return errors.New("request too large")
	}
	var req protocol.Request
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&req); err != nil {
		return errors.New("invalid request")
	}
	if req.Version != protocol.ProtocolVersion {
		return errors.New("unsupported protocol version")
	}
	if !filepath.IsAbs(req.Source) {
		return errors.New("source must be absolute")
	}
	// The parent resolves this from its local registry; there is deliberately no
	// PATH fallback, so an unbound tool fails closed instead of running whichever
	// sops happens to be first on PATH.
	tool, bound := req.Tools["sops"]
	if !bound {
		return errors.New("no sops tool binding in request; run dotenvsec provider retool sops")
	}
	if !filepath.IsAbs(tool.Executable) {
		return errors.New("sops executable must be absolute")
	}
	if tool.SHA256 == "" {
		return errors.New("sops checksum is required")
	}
	sops := tool.Executable
	actual, hashErr := localprovider.FileSHA256(sops)
	if hashErr != nil || !strings.EqualFold(actual, tool.SHA256) {
		return errors.New("sops checksum mismatch")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, sops, "decrypt", "--input-type", "yaml", "--output-type", "yaml", req.Source)
	cmd.Dir = req.Scope.WorktreeRoot
	cmd.Stderr = os.Stderr
	cmd.Env = []string{"HOME=" + os.Getenv("HOME"), "USER=" + os.Getenv("USER"), "PATH=" + os.Getenv("PATH"), "LANG=C", "LC_ALL=C"}
	if req.IdentityPath != "" {
		cmd.Env = append(cmd.Env, "SOPS_AGE_KEY_FILE="+req.IdentityPath)
	}
	plain, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("sops decryption failed")
	}
	defer zero(plain)
	doc, err := config.ParseEnvironment(plain)
	if err != nil {
		return fmt.Errorf("invalid decrypted document: %w", err)
	}
	if err := config.ValidateExactEnvironment(doc.Environment, req.ExpectedNames); err != nil {
		return err
	}
	response := protocol.Response{Version: protocol.ProtocolVersion, Environment: doc.Environment, Unset: req.Unset}
	return json.NewEncoder(os.Stdout).Encode(response)
}

func zero(data []byte) {
	for i := range data {
		data[i] = 0
	}
}
