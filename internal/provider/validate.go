package provider

import (
	"fmt"
	"sort"

	"github.com/philband/dotenvsec/internal/config"
	protocol "github.com/philband/dotenvsec/pkg/provider"
)

func ValidateResponse(response protocol.Response, expected, explicitUnset []string) error {
	if err := config.ValidateExactEnvironment(response.Environment, expected); err != nil {
		return err
	}
	want := append([]string(nil), explicitUnset...)
	got := append([]string(nil), response.Unset...)
	sort.Strings(want)
	sort.Strings(got)
	if fmt.Sprint(want) != fmt.Sprint(got) {
		return fmt.Errorf("provider unset names do not match declaration")
	}
	return nil
}
