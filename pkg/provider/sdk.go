package provider

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

// ServeOne handles one bounded request and writes one protocol response.
func ServeOne(in io.Reader, out io.Writer, handler func(Request) Response) error {
	data, err := io.ReadAll(io.LimitReader(in, MaxMessageBytes+1))
	if err != nil {
		return fmt.Errorf("read request: %w", err)
	}
	if len(data) > MaxMessageBytes {
		return errors.New("request exceeds message limit")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var request Request
	if err := decoder.Decode(&request); err != nil {
		return fmt.Errorf("decode request: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return errors.New("request contains trailing data")
	}
	if request.Version != ProtocolVersion {
		return fmt.Errorf("unsupported protocol version %d", request.Version)
	}
	response := handler(request)
	response.Version = ProtocolVersion
	encoder := json.NewEncoder(out)
	if err := encoder.Encode(response); err != nil {
		return fmt.Errorf("encode response: %w", err)
	}
	return nil
}
