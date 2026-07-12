package provider

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestServeOne(t *testing.T) {
	request, _ := json.Marshal(Request{Version: ProtocolVersion, ExpectedNames: []string{"A"}})
	var output bytes.Buffer
	err := ServeOne(bytes.NewReader(request), &output, func(req Request) Response { return Response{Environment: map[string]string{"A": "value"}} })
	if err != nil {
		t.Fatal(err)
	}
	var response Response
	if err := json.Unmarshal(output.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if response.Version != ProtocolVersion || response.Environment["A"] != "value" {
		t.Fatalf("bad response: %#v", response)
	}
}

func TestServeOneRejectsUnknownFields(t *testing.T) {
	err := ServeOne(bytes.NewBufferString(`{"version":1,"evil":true}`), &bytes.Buffer{}, func(Request) Response { return Response{} })
	if err == nil {
		t.Fatal("unknown field accepted")
	}
}

func TestServeOneRejectsTrailingAndOversizedInput(t *testing.T) {
	for _, input := range []string{`{"version":1} {}`, strings.Repeat(" ", MaxMessageBytes+1)} {
		if err := ServeOne(strings.NewReader(input), &bytes.Buffer{}, func(Request) Response { return Response{} }); err == nil {
			t.Fatal("invalid framing accepted")
		}
	}
}
