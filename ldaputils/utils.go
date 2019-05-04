// Copyright 2019 Aporeto Inc.
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//     http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

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
