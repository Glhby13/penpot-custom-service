package authservice

import (
	"encoding/json"
	"errors"
	"strings"
)

// expandTransit resolves the standard Transit string cache. Responses are then emitted without
// cache references, so changing an opaque token cannot accidentally change a cached sibling.
func expandTransit(v any, cache *[]string, key bool) (any, error) {
	switch x := v.(type) {
	case string:
		if strings.HasPrefix(x, "^") && x != "^ " {
			idx := 0
			for _, c := range x[1:] {
				if c < 48 || c > 91 {
					return nil, errors.New("invalid transit cache")
				}
				idx = idx*44 + int(c-48)
			}
			if len(x) < 2 || idx >= len(*cache) {
				return nil, errors.New("invalid transit reference")
			}
			return (*cache)[idx], nil
		}
		if len(x) > 3 && (key || strings.HasPrefix(x, "~:") || strings.HasPrefix(x, "~$") || strings.HasPrefix(x, "~#")) {
			if len(*cache) >= 1936 {
				*cache = (*cache)[:0]
			}
			*cache = append(*cache, x)
		}
		return x, nil
	case []any:
		out := make([]any, len(x))
		isMap := len(x) > 0 && x[0] == "^ "
		for i, c := range x {
			n, err := expandTransit(c, cache, isMap && i%2 == 1)
			if err != nil {
				return nil, err
			}
			out[i] = n
		}
		return out, nil
	case map[string]any:
		// Backend responses use compact Transit; JSON profile calls are decoded independently.
		return x, nil
	default:
		return x, nil
	}
}
func tokenFields(v any) map[string]any {
	fields := map[string]any{}
	if a, ok := v.([]any); ok && len(a) > 0 && a[0] == "^ " {
		for i := 1; i+1 < len(a); i += 2 {
			if k, ok := a[i].(string); ok {
				fields[strings.TrimPrefix(k, "~:")] = a[i+1]
			}
		}
	}
	if m, ok := v.(map[string]any); ok {
		for k, v := range m {
			fields[strings.TrimPrefix(k, "~:")] = v
		}
	}
	return fields
}
func rewriteMCPToken(v any, wrap func(string) (string, error)) (any, error) {
	fields := tokenFields(v)
	typ, _ := fields["type"].(string)
	if typ == "mcp" {
		if tok, ok := fields["token"].(string); ok && tok != "" {
			replacement, err := wrap(transitUnescape(tok))
			if err != nil {
				return nil, err
			}
			if a, ok := v.([]any); ok {
				for i := 1; i+1 < len(a); i += 2 {
					if a[i] == "~:token" {
						a[i+1] = transitEscape(replacement)
					}
				}
			}
			if m, ok := v.(map[string]any); ok {
				m["token"] = replacement
			}
		}
	}
	if a, ok := v.([]any); ok {
		for i, c := range a {
			if _, ok := c.([]any); ok {
				n, err := rewriteMCPToken(c, wrap)
				if err != nil {
					return nil, err
				}
				a[i] = n
			}
		}
	}
	return v, nil
}
func rewriteTokenBody(body []byte, wrap func(string) (string, error)) ([]byte, error) {
	var v any
	if err := json.Unmarshal(body, &v); err != nil {
		return nil, err
	}
	cache := []string{}
	v, err := expandTransit(v, &cache, false)
	if err != nil {
		return nil, err
	}
	// get-current-mcp-token is deprecated but returns {:token ...} without a type.
	if fields := tokenFields(v); fields["token"] != nil && fields["type"] == nil {
		if a, ok := v.([]any); ok {
			a = append(a, "~:type", "mcp")
			v = a
		}
	}
	v, err = rewriteMCPToken(v, wrap)
	if err != nil {
		return nil, err
	}
	return json.Marshal(v)
}
