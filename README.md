# Midgard Client

This package provides a ready to user Midgard client that can issue and verifies tokens using a running Midgard Server.


## Example with Squall and Manipulate.

The following example shows how to get a Token from Midgard using a certificate, then retrieve the tags in Squall using Manipulate.
For clarity, error checking is volontarily scarse.

```go
package main

import (
    "crypto/tls"
    "crypto/x509"
    "encoding/pem"
    "fmt"
    "io/ioutil"
    "log"

    "github.com/aporeto-inc/manipulate/maniphttp"
    "github.com/aporeto-inc/midgard-lib"
    "golang.org/x/crypto/pkcs12"

    squallModels "github.com/aporeto-inc/gaia/squall/golang"
)

const (
    confCAPath = "path/to/ca.pem"
    confP12Path = "path/to/cert.p12"
    confP12Pass = "aporeto"
)

func main() {

    // Read the CA
    caCert, err := ioutil.ReadFile(confCAPath)
    pool := x509.NewCertPool()
    pool.AppendCertsFromPEM(caCert)

    // Decode the p12
    data, _ := ioutil.ReadFile(confP12Path)
    blocks, _ := pkcs12.ToPEM(data, confP12Pass)
    var pemData []byte
    for _, b := range blocks {
      pemData = append(pemData, pem.EncodeToMemory(b)...)
    }
    cert, _ := tls.X509KeyPair(pemData, pemData)

    // Create a Midgard Client.
    midgardClient := client.NewClient("https://midgard.aporeto.com:8443")

    // Ask Midgard for a new token.
    token, _ := midgardClient.IssueFromCertificate([]tls.Certificate{cert}, pool)

    // create a Manipulate HTTP Store.
    // The username has to be Bearer.
    store := maniphttp.NewHTTPStore("Bearer", token, "https://squall.aporeto.com", "SuperAdmin", maniphttp.NewTLSConfiguration("", "", "", true))

    // Retrieve the tags list using the Manipulate store.
    var dest squallModels.TagsList
    store.RetrieveChildren(nil, nil, squallModels.TagIdentity, &dest); err != nil {

    // Print the tags.
    fmt.Println(dest)
}
```
