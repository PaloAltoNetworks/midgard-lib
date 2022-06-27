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
	"context"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"time"

	"github.com/capitalone/cloud-custodian/tools/omnissm/pkg/aws/ec2metadata"
)

var (
	metadataPath = "http://169.254.169.254/latest/meta-data/"
)

// AWSServiceRoleToken gets the service role data of the VM.
func AWSServiceRoleToken() (roleData string, err error) {

	resp1, err := http.Get(fmt.Sprintf("%siam/security-credentials/", metadataPath))
	if err != nil {
		return "", fmt.Errorf("unable to retrieve role from magic url: %s", err)
	}
	if resp1.StatusCode != http.StatusOK {
		return "", fmt.Errorf("unable to retrieve role from magic url: %s", resp1.Status)
	}

	defer resp1.Body.Close() // nolint: errcheck
	role, err := ioutil.ReadAll(resp1.Body)
	if err != nil {
		return "", fmt.Errorf("unable to read role from aws magic ip: %s", err)
	}

	resp2, err := http.Get(fmt.Sprintf("%siam/security-credentials/%s", metadataPath, role))
	if err != nil {
		return "", fmt.Errorf("unable to retrieve token from magic url: %s", err)
	}
	if resp2.StatusCode != http.StatusOK {
		return "", fmt.Errorf("unable to retrieve token from magic url: %s", resp2.Status)
	}
	defer resp2.Body.Close() // nolint errcheck

	token, err := ioutil.ReadAll(resp2.Body)
	if err != nil {
		return "", fmt.Errorf("unable to read service token information: %s", err)
	}

	return string(token), nil
}

// AWSIdentityToken gets the instance document and its signature
func AWSIdentityDocumentSignature(ctx context.Context, validity time.Duration) (string, string, error) {

	document := ec2metadata.GetLocalInstanceDocument()
	if document == nil {
		return "", "", errors.New("Failed to get aws instance identity document")
	}

	signature := ec2metadata.GetLocalInstanceSignature()
	if signature == nil {
		return "", "", errors.New("Failed to get aws instance identity signature")
	}

	return string(document), string(signature), nil
}
