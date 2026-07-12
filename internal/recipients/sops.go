package recipients

import (
	"bytes"
	"errors"
	"regexp"
	"sort"
	"strings"

	"github.com/philband/dotenvsec/internal/config"
	"gopkg.in/yaml.v3"
)

type document struct {
	CreationRules []rule `yaml:"creation_rules"`
}
type rule struct {
	PathRegex string `yaml:"path_regex"`
	Age       string `yaml:"age"`
}

func GenerateSOPS(manifest config.RecipientManifest, source string) ([]byte, error) {
	var active []string
	for _, item := range manifest.Recipients {
		if item.Status == "active" {
			if strings.ContainsAny(item.Recipient, "\r\n") {
				return nil, errors.New("recipient contains a newline")
			}
			active = append(active, item.Recipient)
		}
	}
	if len(active) == 0 {
		return nil, errors.New("manifest has no active recipients")
	}
	sort.Strings(active)
	return yaml.Marshal(document{CreationRules: []rule{{PathRegex: regexp.QuoteMeta(source) + "$", Age: strings.Join(active, ",")}}})
}

func MatchesSOPS(actual []byte, manifest config.RecipientManifest, source string) error {
	expected, err := GenerateSOPS(manifest, source)
	if err != nil {
		return err
	}
	var actualDoc, expectedDoc document
	if err := config.DecodeStrict(actual, &actualDoc); err != nil {
		return err
	}
	if err := config.DecodeStrict(expected, &expectedDoc); err != nil {
		return err
	}
	a, err := yaml.Marshal(actualDoc)
	if err != nil {
		return err
	}
	e, err := yaml.Marshal(expectedDoc)
	if err != nil {
		return err
	}
	if !bytes.Equal(a, e) {
		return errors.New(".sops.yaml drifts from recipient manifest")
	}
	return nil
}
