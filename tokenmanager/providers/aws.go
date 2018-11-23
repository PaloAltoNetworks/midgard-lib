package providers

import (
	"fmt"
	"io/ioutil"
	"net/http"
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
		return "", fmt.Errorf("Failed to read service token information: %s", err)
	}

	return string(token), nil
}
