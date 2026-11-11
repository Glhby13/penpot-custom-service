package authservice

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strings"
)

// Penpot's frontend talks to its backend in transit+json (a JSON array ["^ ", key, value, ...] for a map, keywords
// written as "~:name"). Only the tiny subset needed for the login command is implemented here.

const transitContentType = "application/transit+json"

// transitUnescape undoes transit's escaping of strings that start with ~, ^ or `.
func transitUnescape(s string) string {
	if len(s) >= 2 && s[0] == '~' && (s[1] == '~' || s[1] == '^' || s[1] == '`') {
		return s[1:]
	}
	return s
}

// transitEscape is the reverse: a string value that starts with ~, ^ or ` gets a leading ~.
func transitEscape(s string) string {
	if s != "" && (s[0] == '~' || s[0] == '^' || s[0] == '`') {
		return "~" + s
	}
	return s
}

func jsonString(s string) string {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(s)
	return strings.TrimSpace(b.String())
}

// decodeLoginBody reads {email, password} from a request body in transit+json (what Penpot's own form sends) or plain JSON.
func decodeLoginBody(body io.Reader) (email, password string, err error) {
	raw, err := io.ReadAll(io.LimitReader(body, 8192))
	if err != nil {
		return "", "", err
	}
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		return "", "", err
	}
	fields := map[string]string{}
	switch t := v.(type) {
	case []any: // transit map: ["^ ", k1, v1, k2, v2, ...]
		if len(t) == 0 || t[0] != "^ " {
			return "", "", errors.New("not a transit map")
		}
		for i := 1; i+1 < len(t); i += 2 {
			k, kok := t[i].(string)
			val, vok := t[i+1].(string)
			if kok && vok {
				fields[strings.TrimPrefix(k, "~:")] = transitUnescape(val)
			}
		}
	case map[string]any: // plain JSON or verbose transit
		for k, val := range t {
			if s, ok := val.(string); ok {
				fields[strings.TrimPrefix(k, "~:")] = transitUnescape(s)
			}
		}
	default:
		return "", "", errors.New("unsupported body")
	}
	email = strings.ToLower(strings.TrimSpace(fields["email"]))
	password = fields["password"]
	if email == "" || password == "" || len(email) > 254 || len(password) > 500 {
		return "", "", errors.New("email and password required")
	}
	return email, password, nil
}

// transitMap builds a transit map from keyword keys to already-encoded string values, in the given order. A caller
// passes a plain string through transitEscape and a keyword as "~:name".
func transitMap(pairs ...string) []byte {
	var b bytes.Buffer
	b.WriteString(`["^ "`)
	for i := 0; i+1 < len(pairs); i += 2 {
		b.WriteString(",")
		b.WriteString(jsonString("~:" + pairs[i]))
		b.WriteString(",")
		b.WriteString(jsonString(pairs[i+1]))
	}
	b.WriteString("]")
	return b.Bytes()
}

// transitError builds the error map Penpot's frontend understands: {:type <type>, :code <code>, :hint <hint>}.
func transitError(typ, code, hint string) []byte {
	return transitMap("type", "~:"+typ, "code", "~:"+code, "hint", transitEscape(hint))
}
