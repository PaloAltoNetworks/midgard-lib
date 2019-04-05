package ldaputils

import "fmt"

func findLDAPKey(k string, metadata map[string]interface{}) (string, error) {

	v, ok := metadata[k]
	if !ok {
		return "", fmt.Errorf("metadata must contain the key '%s'", k)
	}

	if s, ok := v.(string); ok && s != "" {
		return s, nil
	}

	return "", fmt.Errorf("metadata must be a string for key '%s'", k)
}

func findLDAPKeyMap(k string, metadata map[string]interface{}) (m map[string]interface{}, e error) {

	v, ok := metadata[k]
	if !ok {
		return nil, fmt.Errorf("metadata must contain the key '%s'", k)
	}

	l, ok := v.([]string)
	if !ok {
		return nil, fmt.Errorf("metadata must be a list of strings for key '%s'", k)
	}

	m = make(map[string]interface{})
	for _, key := range l {
		m[key] = nil
	}
	return m, nil
}
