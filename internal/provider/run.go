package provider

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"time"

	"github.com/philband/dotenvsec/internal/config"
	protocol "github.com/philband/dotenvsec/pkg/provider"
)

func Run(ctx context.Context, entry config.ProviderEntry, req protocol.Request) (protocol.Response, error) {
	var response protocol.Response
	if err := Verify(entry); err != nil {
		return response, fmt.Errorf("verify provider: %w", err)
	}
	timeout := entry.Timeout.Duration
	if timeout <= 0 {
		timeout = 2 * time.Minute
	}
	if timeout > 10*time.Minute {
		timeout = 10 * time.Minute
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	payload, err := json.Marshal(req)
	if err != nil {
		return response, err
	}
	if len(payload) > protocol.MaxMessageBytes {
		return response, errors.New("provider request too large")
	}
	path, err := SafePath(req.Config["plugin_path"])
	if err != nil {
		return response, err
	}
	cmd := exec.CommandContext(ctx, entry.Executable)
	cmd.Dir = req.Scope.WorktreeRoot
	cmd.Env = []string{"HOME=" + os.Getenv("HOME"), "USER=" + os.Getenv("USER"), "LOGNAME=" + os.Getenv("LOGNAME"), "PATH=" + path, "LANG=C.UTF-8"}
	cmd.Stdin = bytes.NewReader(payload)
	cmd.Stderr = os.Stderr
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return response, err
	}
	if err := cmd.Start(); err != nil {
		return response, err
	}
	data, readErr := io.ReadAll(io.LimitReader(stdout, protocol.MaxMessageBytes+1))
	waitErr := cmd.Wait()
	if ctx.Err() != nil {
		return response, fmt.Errorf("provider cancelled or timed out: %w", ctx.Err())
	}
	if readErr != nil {
		return response, fmt.Errorf("read provider response: %w", readErr)
	}
	if len(data) > protocol.MaxMessageBytes {
		return response, errors.New("provider response too large")
	}
	if waitErr != nil {
		return response, fmt.Errorf("provider failed: %w", waitErr)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&response); err != nil {
		return response, fmt.Errorf("decode provider response: %w", err)
	}
	if err := ensureJSONEOF(decoder); err != nil {
		return response, err
	}
	if response.Version != protocol.ProtocolVersion {
		return response, errors.New("provider protocol version mismatch")
	}
	if response.Error != nil {
		return response, fmt.Errorf("provider %s: %s", response.Error.Code, response.Error.Message)
	}
	return response, nil
}

func ensureJSONEOF(decoder *json.Decoder) error {
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return errors.New("provider stdout contains extra data")
	}
	return nil
}
