package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"strings"

	"github.com/aporeto-inc/midgard-lib/client"
	"golang.org/x/crypto/pkcs12"

	log "github.com/Sirupsen/logrus"
	docopt "github.com/docopt/docopt-go"
)

const (
	versionString = "0.0.1"
	usage         = `Midgard Client.

Usage: midgardctl -h | --help
       midgardctl -v | --version
       midgardctl issue-cert
         --ca=<path>
         --p12=<path>
         --password=<password>
         [--url=<url>]
         [--pretty]
       midgardctl issue-google
         --token=<token>
         [--url=<url>]
         [--pretty]
       midgardctl auth
         --token=<token>
         [--url=<url>]
         [--pretty]

Options:
    -h --help               Show this screen.
    -v --version            Show the version.
    --ca=<path>             Path of the CA to use.
    --p12=<path>            Path of the client p12 to use.
    --password=<password>   Password to decrypt the p12.
    --url=<url>             URL of the Midgard server [default: https://midgard.aporeto.com:8443].
    --token=<token>         Token to use.
    --pretty                If set, print human friendly output.
`
)

func main() {

	args, err := docopt.Parse(usage, nil, true, versionString, false)
	if err != nil {
		log.Fatal("Invalid arguments")
	}

	if args["issue-cert"].(bool) {
		issueFromCertificate(
			args["--url"].(string),
			args["--p12"].(string),
			args["--password"].(string),
			args["--ca"].(string),
			args["--pretty"].(bool),
		)
	}

	if args["issue-google"].(bool) {
		issueFromGoogle(
			args["--url"].(string),
			args["--token"].(string),
			args["--pretty"].(bool),
		)
	}

	if args["auth"].(bool) {
		authentify(
			args["--url"].(string),
			args["--token"].(string),
			args["--pretty"].(bool),
		)
	}
}

// issueFromGoogle issues a new Midgard token from a Google token.
func issueFromGoogle(url, token string, pretty bool) {

	client := midgardclient.NewClient(url)
	token, err := client.IssueFromGoogle(token)

	if err != nil {
		fmt.Printf("\033[0;31mUnable to issue token.\033[0m\n")
		return
	}

	printIssuingResult(token, pretty)
}

// issueFromCertificate issues a new Midgard token from a certiticate.
func issueFromCertificate(url, p12Path, p12Password, CAPath string, pretty bool) {

	data, err := ioutil.ReadFile(p12Path)
	if err != nil {
		log.Fatalf("Unable find p12: %s", err.Error())
	}

	blocks, err := pkcs12.ToPEM(data, p12Password)
	if err != nil {
		log.Fatalf("Unable decrypt p12: %s", err.Error())
	}

	var pemData []byte
	for _, b := range blocks {
		pemData = append(pemData, pem.EncodeToMemory(b)...)
	}

	cert, err := tls.X509KeyPair(pemData, pemData)
	if err != nil {
		log.Fatalf("Unable load certificate: %s", err.Error())
	}

	caCert, err := ioutil.ReadFile(CAPath)

	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(caCert)

	client := midgardclient.NewClientWithCAPool(url, pool, nil, true)

	token, err := client.IssueFromCertificate([]tls.Certificate{cert})
	if err != nil {
		fmt.Printf("\033[0;31mUnable to issue token.\033[0m.\n")
		return
	}

	printIssuingResult(token, pretty)
}

// authentify authentifies the given token against Midgard.
func authentify(url, token string, pretty bool) {

	client := midgardclient.NewClient(url)

	_, err := client.Authentify(token)
	if err != nil {
		fmt.Printf("\033[0;31mToken is invalid\033[0m.\n")
		return
	}

	if pretty {
		fmt.Printf("Token Status: \033[0;32mVALID\033[0m\n%s\n", formatToken(token))
	}
}

// formatToken parses the token and returns a human readable string representing the claims.
func formatToken(token string) string {

	claims := strings.Split(token, ".")[1]
	data, err := base64.RawStdEncoding.DecodeString(claims)
	if err != nil {
		log.Fatalf("Unable to decode token: %s", err.Error())
	}

	var m interface{}

	if err := json.Unmarshal(data, &m); err != nil {
		log.Fatalf("Unable to convert token: %s", err.Error())
	}

	var ret []byte
	ret, err1 := json.MarshalIndent(m, "", "  ")
	if err1 != nil {
		log.Fatalf("Unable to prettyfy token: %s", err1.Error())
	}

	return string(ret)
}

// printIssuingResult prints the result of issue request.
func printIssuingResult(token string, pretty bool) {

	if pretty {
		fmt.Printf("\n%s\n\n%s\n", token, formatToken(token))
	} else {
		fmt.Println(token)
	}
}
