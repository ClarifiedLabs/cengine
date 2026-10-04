//go:build ignore

// Public-only deterministic cross-language fixture. These test keys are never trusted in production.
package main

import (
 "crypto/ed25519"
 "crypto/rand"
 "crypto/x509"
 "crypto/x509/pkix"
 "encoding/base64"
 "encoding/json"
 "math/big"
 "os"
 "time"
)
func main(){
 seed:=make([]byte,32);for i:=range seed{seed[i]=3};key:=ed25519.NewKeyFromSeed(seed)
 now:=time.Date(2026,9,10,0,0,0,0,time.UTC)
 ca:=&x509.Certificate{SerialNumber:big.NewInt(1),Subject:pkix.Name{CommonName:"storage startup fixture ONLY"},NotBefore:now,NotAfter:now.Add(time.Hour),IsCA:true,BasicConstraintsValid:true,MaxPathLen:0,MaxPathLenZero:true,KeyUsage:x509.KeyUsageCertSign}
 der,err:=x509.CreateCertificate(rand.Reader,ca,ca,key.Public(),key);if err!=nil{panic(err)}
 spki,err:=x509.MarshalPKIXPublicKey(key.Public());if err!=nil{panic(err)}
 store:="11111111-1111-4111-8111-111111111111";incarnation:="22222222-2222-4222-8222-222222222222"
 initialization:=map[string]any{"daemon_unique_id":^uint64(0),"expected_epoch":^uint64(0),"incarnation_id":incarnation,"store":store,"version":"child-init.v2"}
 greeting:=map[string]any{"controller_spki":base64.StdEncoding.EncodeToString(spki),"daemon_unique_id":^uint64(0),"expected_epoch":^uint64(0),"incarnation_id":incarnation,"store":store,"version":"child-key.v2"}
 binding:=map[string]any{"root_der":base64.StdEncoding.EncodeToString(der),"server_spki":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","service_epoch":"33333333-3333-4333-8333-333333333333","store":store,"version":"service-bind.v2"}
 encoder:=json.NewEncoder(os.Stdout);encoder.SetIndent("","  ");if err=encoder.Encode(map[string]any{"initialization":initialization,"key_greeting":greeting,"service_binding":binding});err!=nil{panic(err)}
}
