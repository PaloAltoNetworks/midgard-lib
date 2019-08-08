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

package providers

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
)

// AzureToken is the standard OAUTH token provided by Azure.
type AzureToken struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    string `json:"expires_in"`
	ExpiresOn    string `json:"expires_on"`
	NotBefore    string `json:"not_before"`
	Resource     string `json:"resource"`
	TokenType    string `json:"token_type"`
}

var (
	azureServiceTokenURL = "http://169.254.169.254/metadata/identity/oauth2/token" // #nosec
)

// AzureServiceIdentityToken will retrieve the service account token for
// the VM using the Metadata Identity Service of Azure.
func AzureServiceIdentityToken() (string, error) {
	body, err := issueRequest(azureServiceTokenURL)
	if err != nil {
		return "", err
	}

	// Unmarshall response body into struct
	token := &AzureToken{}

	err = json.Unmarshal(body, token)
	if err != nil {
		return "", fmt.Errorf("invalid token returned by metadata service: %s", err)
	}

	return token.AccessToken, nil
}

func issueRequest(baseuri string) ([]byte, error) {
	var endpoint *url.URL
	endpoint, err := url.Parse(baseuri)
	if err != nil {
		return nil, fmt.Errorf("unable to access the service account URL: %s", err)
	}

	parameters := url.Values{}
	parameters.Add("api-version", "2018-02-01")
	parameters.Add("resource", "https://management.azure.com")

	endpoint.RawQuery = parameters.Encode()
	req, err := http.NewRequest("GET", endpoint.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("unable to create HTTP request: %s", err)
	}
	req.Header.Add("Metadata", "true")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("unable to issue request: %s", err)
	}

	defer resp.Body.Close() // nolint errcheck
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("unable to read data: %s", err)
	}

	return body, nil
}
