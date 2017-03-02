package ldaputils

import "fmt"

func findLDAPKey(k string, metadata map[string]interface{}) (string, error) {

	if v, ok := metadata[k]; ok && v.(string) != "" {
		return v.(string), nil
	}

	return "", fmt.Errorf("Metadata must contain the key '%s'", k)
}
