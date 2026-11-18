package main

import (
	"encoding/base64"
	"testing"
)

func fakeJWT(payload string) string {
	return "e30." + base64.RawURLEncoding.EncodeToString([]byte(payload)) + ".sig"
}

func TestProcessCallback(t *testing.T) {
	idToken := fakeJWT(`{"nonce":"n1","sub":"bob"}`)

	r, err := processCallback(map[string]string{"state": "s1", "id_token": idToken, "access_token": "opaque"}, "s1", "n1")
	if err != nil || r.IDToken != idToken || r.AccessToken != "opaque" {
		t.Fatalf("valid callback: %v %+v", err, r)
	}
	if _, err := processCallback(map[string]string{"state": "s1", "id_token": idToken}, "s1", "other"); err == nil {
		t.Fatal("nonce mismatch accepted")
	}
	if _, err := processCallback(map[string]string{"state": "s1", "id_token": "garbage"}, "s1", "n1"); err == nil {
		t.Fatal("malformed id_token accepted")
	}
	if _, err := processCallback(map[string]string{"state": "s1"}, "s1", "n1"); err == nil {
		t.Fatal("missing tokens accepted")
	}
	if _, err := processCallback(map[string]string{"state": "s1", "access_token": "opaque"}, "s1", "n1"); err != nil {
		t.Fatalf("access_token-only rejected: %v", err)
	}
}
