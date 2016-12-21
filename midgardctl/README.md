# Midgardctl

midgardctl is a small command line utilities that uses the Midgard Client to issue and authentify Midgard tokens.

### Installation

Simply run:

    $ go get github.com/aporeto-inc/midgard-lib/midgardctl

### Usage

To get a token from a certificate:

    $ midgardctl issue-cert --p12 /path/to/client.p12 --password secret --ca /path/to/ca.pem --url https://midgard.aporeto.com:8443 --pretty

    eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJyZWFsbSI6ImNlcnRpZmljYXRlIiwiZGF0YSI6eyJjb21tb25OYW1lIjoic3VwZXJhZG1pbiIsIm9yZ2FuaXphdGlvbiI6ImFwb3JldG8uY29tIiwib3JnYW5pemF0aW9uYWxVbml0IjoiU3VwZXJBZG1pbiJ9LCJhdWQiOiJhcG9yZXRvLmNvbSIsImV4cCI6MTQ3NTA5NTQwNywiaWF0IjoxNDc1MDA5MDA3LCJpc3MiOiJtaWRnYXJkLmFwb3JldG8uY29tIiwic3ViIjoiMTAyMzcyMDczNDQyOTkzNDM0ODkifQ.wBg0kJqJRVf9q-RH161NwXpIy8qR0JwvmIDYitffA64

    {
      "aud": "aporeto.com",
      "data": {
        "commonName": "superadmin",
        "organization": "aporeto.com",
        "organizationalUnit": "SuperAdmin"
      },
      "exp": 1.475095407e+09,
      "iat": 1.475009007e+09,
      "iss": "midgard.aporeto.com",
      "realm": "certificate",
      "sub": "10237207344299343489"
    }

To get a token from a Google JWT:

    $ midgardctl issue-google --token=<google-jwt>
      eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJyZWFsbSI6Imdvb2dsZSIsImRhdGEiOnsiZW1haWwiOiJhbnRvaW5lLm1lcmNhZGFsQGdtYWlsLmNvbSIsImZhbWlseU5hbWUiOiJNZXJjYWRhbCIsImdpdmVuTmFtZSI6IkFudG9pbmUiLCJuYW1lIjoiQW50b2luZSBNZXJjYWRhbCJ9LCJhdWQiOiJhcG9yZXRvLmNvbSIsImV4cCI6MTQ3NTA5NTU1MCwiaWF0IjoxNDc1MDA5MTUwLCJpc3MiOiJtaWRnYXJkLmFwb3JldG8uY29tIiwic3ViIjoiMTE2MzY1NDg1NDE0NDQ4Mjg3MDg4In0.cqmdYCVEX495nHws0rw9StI-2e9gqOaTTrUR_eCy7vs

> Note: here we don't use the flag `--pretty` so only the token is printed


To authentify a Midgard token:

    $ ./midgardctl auth --token=$JWT --pretty
    Token Status: VALID
    {
      "aud": "aporeto.com",
      "data": {
        "email": "antoine.mercadal@gmail.com",
        "familyName": "Mercadal",
        "givenName": "Antoine",
        "name": "Antoine Mercadal"
      },
      "exp": 1.47509555e+09,
      "iat": 1.47500915e+09,
      "iss": "midgard.aporeto.com",
      "realm": "google",
      "sub": "116365485414448287088"
    }
