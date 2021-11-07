// jwtverify is a utility to parse and verify the signatures of JWTs.
package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"

	"gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"
)

func main() {
	if len(os.Args) < 3 {
		fmt.Fprintln(os.Stderr, "Usage: jwtverify {JWT} {JWKS Endpoint}")
		os.Exit(1)
	}

	if err := validateToken(os.Args[1], os.Args[2]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

type customToken struct {
	jwt.Claims
	Foo string `json:"foo"`
}

func validateToken(rawToken, jwksEndpoint string) error {
	tok, err := jwt.ParseSigned(rawToken)
	if err != nil {
		return err
	}

	resp, err := http.Get(jwksEndpoint)
	if err != nil {
		return err
	}

	defer resp.Body.Close()
	jwksBody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	var jwks jose.JSONWebKeySet
	if err = json.Unmarshal(jwksBody, &jwks); err != nil {
		return err
	}

	var kid string
	for _, header := range tok.Headers {
		if header.KeyID != "" {
			kid = header.KeyID
			break
		}
	}

	if kid == "" {
		return errors.New("no kid header set")
	}

	matchingKeys := jwks.Key(kid)
	if len(matchingKeys) == 0 {
		return fmt.Errorf("no matching keys for kid %s", kid)
	}
	if len(matchingKeys) > 1 {
		return fmt.Errorf("multiple matching keys for kid %s\n%s", kid, jwksBody)
	}

	cl := customToken{}
	if err = tok.Claims(matchingKeys[0].Key, &cl); err != nil {
		return fmt.Errorf("%s\n%s\n%s", err, rawToken, jwksBody)
	}

	jsonClaims, err := json.Marshal(cl)
	if err != nil {
		return fmt.Errorf("error serializing decoded claims: %v", err)
	}

	fmt.Printf("%s\n", jsonClaims)

	return nil
}
