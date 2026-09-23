package guardrail

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"

	"go.yaml.in/yaml/v3"
)

// DecodePolicy accepts one YAML (or JSON) document. Convert through JSON so
// unstructured rubric values and policy fields share the REST model's types.
func DecodePolicy(data []byte) (Policy, error) {
	var p Policy
	err := DecodeDocument(data, &p)
	return p, err
}

// DecodeDocument strictly decodes a single JSON-compatible YAML mapping.
func DecodeDocument(data []byte, target any) error {
	if len(data) > 1<<20 {
		return fmt.Errorf("policy exceeds 1 MiB")
	}
	d := yaml.NewDecoder(bytes.NewReader(data))
	var root yaml.Node
	if err := d.Decode(&root); err != nil {
		return fmt.Errorf("invalid policy YAML: %w", err)
	}
	var extra yaml.Node
	if err := d.Decode(&extra); err != io.EOF {
		return fmt.Errorf("provide exactly one policy document")
	}
	if len(root.Content) != 1 || root.Content[0].Kind != yaml.MappingNode {
		return fmt.Errorf("policy must be a mapping")
	}
	if err := checkYAML(&root); err != nil {
		return err
	}
	var value any
	if err := root.Decode(&value); err != nil {
		return err
	}
	b, err := json.Marshal(value)
	if err != nil {
		return fmt.Errorf("policy must contain JSON-compatible values: %w", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(b))
	decoder.DisallowUnknownFields()
	if err = decoder.Decode(target); err != nil {
		return err
	}
	return nil
}
func checkYAML(n *yaml.Node) error {
	if n.Kind == yaml.AliasNode || n.Anchor != "" {
		return fmt.Errorf("YAML anchors and aliases are not supported; define criteria explicitly")
	}
	if n.Kind == yaml.ScalarNode {
		switch n.Tag {
		case "!!str", "!!bool", "!!int", "!!float", "!!null":
		default:
			return fmt.Errorf("unsupported YAML tag %s; quote dates and other text values", n.Tag)
		}
	}
	if n.Kind == yaml.MappingNode {
		seen := map[string]bool{}
		for i := 0; i < len(n.Content); i += 2 {
			k := n.Content[i]
			if k.Kind != yaml.ScalarNode || k.Tag != "!!str" {
				return fmt.Errorf("YAML mapping keys must be strings; quote true and false anchors")
			}
			if seen[k.Value] {
				return fmt.Errorf("duplicate YAML key %q", k.Value)
			}
			seen[k.Value] = true
		}
	}
	for _, child := range n.Content {
		if err := checkYAML(child); err != nil {
			return err
		}
	}
	return nil
}
func MarshalPolicy(p Policy) ([]byte, error) {
	// Decode JSON into a YAML node to preserve field order and string semantics.
	b, err := json.Marshal(p)
	if err != nil {
		return nil, err
	}
	var n yaml.Node
	if err = yaml.Unmarshal(b, &n); err != nil {
		return nil, err
	}
	var block func(*yaml.Node)
	block = func(n *yaml.Node) {
		n.Style = 0
		for _, c := range n.Content {
			block(c)
		}
	}
	block(&n)
	var out bytes.Buffer
	e := yaml.NewEncoder(&out)
	e.SetIndent(2)
	if err = e.Encode(&n); err != nil {
		return nil, err
	}
	if err = e.Close(); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}
