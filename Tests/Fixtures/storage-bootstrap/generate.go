// Test-only known seeds. NEVER use these keys in a helper or production store.
// Run from the repository root:
//
//	go run Tests/Fixtures/storage-bootstrap/generate.go > Tests/Fixtures/storage-bootstrap/vectors.json
//	go run Tests/Fixtures/storage-bootstrap/generate.go -check Tests/Fixtures/storage-bootstrap/vectors.json
//
// Standard-library-only cross-language oracle. Grant and grantSigningBytes mirror
// Guest/internal/storageauthority/{types.go,auth.go}: declaration order matters.
package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
)

type Grant struct {
	ID            string `json:"id"`
	Store         string `json:"store"`
	ExpectedEpoch uint64 `json:"expected_epoch"`
	NewKey        string `json:"new_key"`
}

func grantSigningBytes(g Grant) []byte {
	b, err := json.Marshal(g)
	if err != nil {
		panic(err)
	}
	return append([]byte("cengine.storageauthority.takeover.v1\x00"), b...)
}

type vector struct {
	Grant        Grant  `json:"grant"`
	GrantJSON    string `json:"grant_json"`
	SigningBytes string `json:"signing_bytes_base64"`
	Signature    string `json:"signature_hex"`
}

type fixture struct {
	Warning               string   `json:"warning"`
	RootSeed              string   `json:"root_seed_hex"`
	RootPublicKey         string   `json:"root_public_key_hex"`
	RootSPKI              string   `json:"root_spki_base64"`
	RootFingerprint       string   `json:"root_fingerprint"`
	RFC8032EmptySignature string   `json:"rfc8032_empty_signature_hex"`
	ControllerSeed        string   `json:"controller_seed_hex"`
	ControllerSPKI        string   `json:"controller_spki_base64"`
	ControllerFingerprint string   `json:"controller_fingerprint"`
	Vectors               []vector `json:"vectors"`
}

func key(seed string) ed25519.PrivateKey {
	b, err := hex.DecodeString(seed)
	if err != nil {
		panic(err)
	}
	return ed25519.NewKeyFromSeed(b)
}
func spki(key ed25519.PrivateKey) []byte {
	der, err := x509.MarshalPKIXPublicKey(key.Public())
	if err != nil {
		panic(err)
	}
	return der
}
func fingerprint(der []byte) string {
	digest := sha256.Sum256(der)
	return hex.EncodeToString(digest[:])
}
func main() {
	check := flag.String("check", "", "compare checked-in fixture without writing")
	flag.Parse()
	f := fixture{
		Warning:        "TEST ONLY: public RFC 8032 seeds; never production authority keys",
		RootSeed:       "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
		ControllerSeed: "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
	}
	root, controller := key(f.RootSeed), key(f.ControllerSeed)
	f.RootPublicKey = hex.EncodeToString(root.Public().(ed25519.PublicKey))
	f.RootSPKI = base64.StdEncoding.EncodeToString(spki(root))
	f.RootFingerprint = fingerprint(spki(root))
	f.RFC8032EmptySignature = hex.EncodeToString(ed25519.Sign(root, nil))
	f.ControllerSPKI = base64.StdEncoding.EncodeToString(spki(controller))
	f.ControllerFingerprint = fingerprint(spki(controller))
	for _, epoch := range []uint64{1, 9007199254740993, ^uint64(0) - 1} {
		g := Grant{"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", "bbbbbbbb-bbbb-4bbb-9bbb-bbbbbbbbbbbb", epoch, f.ControllerFingerprint}
		body, err := json.Marshal(g)
		if err != nil {
			panic(err)
		}
		msg := grantSigningBytes(g)
		sig := ed25519.Sign(root, msg)
		if !ed25519.Verify(root.Public().(ed25519.PublicKey), msg, sig) {
			panic("invalid vector")
		}
		f.Vectors = append(f.Vectors, vector{g, string(body), base64.StdEncoding.EncodeToString(msg), hex.EncodeToString(sig)})
	}
	out, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		panic(err)
	}
	out = append(out, '\n')
	if *check != "" {
		got, err := os.ReadFile(*check)
		if err != nil {
			panic(err)
		}
		if !bytes.Equal(got, out) {
			fmt.Fprintln(os.Stderr, "storage bootstrap fixture mismatch")
			os.Exit(1)
		}
		fmt.Println("storage bootstrap fixture matches Go standard-library oracle")
		return
	}
	_, _ = os.Stdout.Write(out)
}
