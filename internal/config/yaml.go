package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

var envNameRE = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

func DecodeFile(path string, out any) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if len(data) > MaxYAMLBytes {
		return fmt.Errorf("YAML exceeds %d bytes", MaxYAMLBytes)
	}
	return DecodeStrict(data, out)
}

func DecodeStrict(data []byte, out any) error {
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	var doc yaml.Node
	if err := dec.Decode(&doc); err != nil {
		return fmt.Errorf("decode YAML: %w", err)
	}
	if len(doc.Content) != 1 {
		return errors.New("YAML must contain exactly one document")
	}
	if err := validateNode(doc.Content[0], "$"); err != nil {
		return err
	}
	var extra yaml.Node
	if err := dec.Decode(&extra); err != io.EOF {
		return errors.New("multiple YAML documents are forbidden")
	}
	// Decode again after structural validation so KnownFields is applied to out.
	dec = yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(out); err != nil {
		return fmt.Errorf("validate YAML fields: %w", err)
	}
	return nil
}

func validateNode(node *yaml.Node, path string) error {
	if node.Alias != nil || node.Kind == yaml.AliasNode || node.Anchor != "" {
		return fmt.Errorf("%s: aliases and anchors are forbidden", path)
	}
	if strings.HasPrefix(node.Tag, "!") && !strings.HasPrefix(node.Tag, "!!") {
		return fmt.Errorf("%s: custom YAML tags are forbidden", path)
	}
	switch node.Kind {
	case yaml.MappingNode:
		seen := map[string]struct{}{}
		for i := 0; i < len(node.Content); i += 2 {
			key, value := node.Content[i], node.Content[i+1]
			if key.Kind != yaml.ScalarNode || key.Tag != "!!str" {
				return fmt.Errorf("%s: mapping keys must be strings", path)
			}
			if _, ok := seen[key.Value]; ok {
				return fmt.Errorf("%s: duplicate key %q", path, key.Value)
			}
			seen[key.Value] = struct{}{}
			if err := validateNode(value, path+"."+key.Value); err != nil {
				return err
			}
		}
	case yaml.SequenceNode:
		for i, child := range node.Content {
			if err := validateNode(child, fmt.Sprintf("%s[%d]", path, i)); err != nil {
				return err
			}
		}
	case yaml.ScalarNode:
		if node.Style == 0 && (node.Tag == "!!bool" || node.Tag == "!!int" || node.Tag == "!!float" || node.Tag == "!!timestamp" || node.Tag == "!!null") {
			// Typed fields are allowed to consume these; environment values are checked separately.
			return nil
		}
	default:
		return fmt.Errorf("%s: unsupported YAML node", path)
	}
	return nil
}

func LoadScope(path string) (Scope, error) {
	var c Scope
	if err := DecodeFile(path, &c); err != nil {
		return c, err
	}
	if c.Schema != ScopeSchemaVersion {
		return c, fmt.Errorf("unsupported scope schema %d", c.Schema)
	}
	if c.Provider == "" || c.Source == "" {
		return c, errors.New("provider and source are required")
	}
	if len(c.Environment) > MaxEnvironmentVariables {
		return c, errors.New("too many environment names")
	}
	if err := validateNameLists(c.Environment, c.Unset, c.AllowDangerous); err != nil {
		return c, err
	}
	return c, nil
}

func LoadRecipients(path string) (RecipientManifest, error) {
	var m RecipientManifest
	if err := DecodeFile(path, &m); err != nil {
		return m, err
	}
	if m.Schema != RecipientsSchemaVersion {
		return m, fmt.Errorf("unsupported recipients schema %d", m.Schema)
	}
	ids, recipients := map[string]bool{}, map[string]bool{}
	for _, r := range m.Recipients {
		if r.ID == "" || r.Owner == "" || r.Recipient == "" {
			return m, errors.New("recipient id, owner, and recipient are required")
		}
		if strings.ContainsAny(r.ID+r.Owner+r.Recipient, "\r\n") {
			return m, errors.New("recipient fields must not contain newlines")
		}
		if ids[r.ID] {
			return m, fmt.Errorf("duplicate recipient id %q", r.ID)
		}
		ids[r.ID] = true
		if recipients[r.Recipient] {
			return m, errors.New("duplicate public recipient")
		}
		recipients[r.Recipient] = true
		if r.Status != "active" && r.Status != "revoked" {
			return m, fmt.Errorf("recipient %q has invalid status", r.ID)
		}
		if r.Plugin != "yubikey" && r.Plugin != "secure-enclave" && r.Plugin != "age" {
			return m, fmt.Errorf("recipient %q uses unsupported plugin", r.ID)
		}
		if strings.HasPrefix(r.Recipient, "age1tag") {
			return m, fmt.Errorf("recipient %q uses an unverified age tag format", r.ID)
		}
	}
	return m, nil
}

func ParseEnvironment(data []byte) (EnvironmentDocument, error) {
	var doc EnvironmentDocument
	if len(data) > MaxEnvironmentBytes {
		return doc, errors.New("decrypted environment exceeds size limit")
	}
	var root yaml.Node
	if err := DecodeStrict(data, &root); err != nil {
		return doc, err
	}
	if err := requireEnvironmentStrings(&root); err != nil {
		return doc, err
	}
	if err := DecodeStrict(data, &doc); err != nil {
		return doc, err
	}
	if doc.Environment == nil {
		return doc, errors.New("document must contain exactly one environment mapping")
	}
	if len(doc.Environment) > MaxEnvironmentVariables {
		return doc, errors.New("too many environment variables")
	}
	total := 0
	for k, v := range doc.Environment {
		if !envNameRE.MatchString(k) {
			return doc, fmt.Errorf("invalid environment name %q", k)
		}
		if strings.IndexByte(v, 0) >= 0 {
			return doc, fmt.Errorf("environment value for %q contains NUL", k)
		}
		total += len(k) + len(v)
	}
	if total > MaxEnvironmentBytes {
		return doc, errors.New("environment exceeds total size limit")
	}
	return doc, nil
}

func requireEnvironmentStrings(document *yaml.Node) error {
	if len(document.Content) != 1 || document.Content[0].Kind != yaml.MappingNode {
		return errors.New("document root must be a mapping")
	}
	root := document.Content[0]
	if len(root.Content) != 2 || root.Content[0].Value != "environment" || root.Content[1].Kind != yaml.MappingNode {
		return errors.New("document must contain exactly one environment mapping")
	}
	values := root.Content[1]
	for i := 0; i < len(values.Content); i += 2 {
		if values.Content[i+1].Kind != yaml.ScalarNode || values.Content[i+1].Tag != "!!str" {
			return fmt.Errorf("environment value for %q must be an explicit YAML string", values.Content[i].Value)
		}
	}
	return nil
}

func ValidateExactEnvironment(actual map[string]string, expected []string) error {
	want := append([]string(nil), expected...)
	sort.Strings(want)
	got := make([]string, 0, len(actual))
	for k := range actual {
		got = append(got, k)
	}
	sort.Strings(got)
	if strings.Join(want, "\x00") != strings.Join(got, "\x00") {
		return fmt.Errorf("provider output names do not match declared environment")
	}
	return nil
}

func validateNameLists(lists ...[]string) error {
	seen := map[string]bool{}
	for _, list := range lists {
		for _, name := range list {
			if !envNameRE.MatchString(name) {
				return fmt.Errorf("invalid environment name %q", name)
			}
			if seen[name] {
				return fmt.Errorf("duplicate environment name %q", name)
			}
			seen[name] = true
		}
	}
	return nil
}
