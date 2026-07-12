package provider

import (
	protocol "github.com/philband/dotenvsec/pkg/provider"
	"testing"
)

func TestValidateResponse(t *testing.T) {
	good := protocol.Response{Environment: map[string]string{"A": "v"}, Unset: []string{"B"}}
	if err := ValidateResponse(good, []string{"A"}, []string{"B"}); err != nil {
		t.Fatal(err)
	}
	good.Unset = []string{"C"}
	if err := ValidateResponse(good, []string{"A"}, []string{"B"}); err == nil {
		t.Fatal("undeclared unset accepted")
	}
}
