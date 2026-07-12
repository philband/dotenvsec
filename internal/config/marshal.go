package config

import "gopkg.in/yaml.v3"

func yamlMarshal(value any) ([]byte, error) { return yaml.Marshal(value) }
func Marshal(value any) ([]byte, error)     { return yamlMarshal(value) }
