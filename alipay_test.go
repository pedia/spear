package alipay

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"log"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestPemSignVerify(t *testing.T) {
	is := assert.New(t)
	raw_bytes := []byte("MIIEpAIBAAKCAQEAtrCYn039gp/IjLZsNl64QjHjPfAklyYZyIPSqlPNmColRMOAb2rbnLASRpP1VgT7YzA4JgJ1f/fhGsSBexpIi2BOZdwDexBtmfe9dFGzbWhpqAxzWnZazLde+BGOs6BGk0v1B0cWUqlv6wgSSo57Xu7xL56a34gDsBi1qoXnu4f1CzrvviRsNCgDDurNsAtkjLzoPuzHri6sThsQ7P3amb3zyG5xVxSGZRFKgPNoiiZpBpXPoEwMrHQRE8rmsmgdz+E4YL1xuD+ICQxCCTBOJwUuDzPt5wr793Pxgloqh0p3yPvOShmbMAxUtLiGgcZNqxy49ddG89egVyGxRJpimQIDAQABAoIBAEfGUfAkn/j19cDy2sjxpcq79t+avYV0vqR8xgONMTUbOdEuTgN4JBgHRObdsoG9K1bo1uZ4CNnh9Vqi4YwP43h+uc5jBisPZUAciR5uCuRtJTWUzq032qybToB/xWTlD1VHflkBoM+RKhtY7HbGS8ocbj2bPpWbxnck/hqkyUpvkFkO0/ngHr6V44pxEK7sm53abiey4jtAQwJcLgS3wLcbSbVGsfRI1srq1I1s54EKzZfJxqRynuMiaKDPGHrUHEcNCQcWS3k4cU1sZF5jMk17f97SzwC8Iz0Kfd7zzw8IiGmvX7sYHJL0mPwqAF+rSlVwZs+Fj/DDcFcBHvpSlBECgYEA+BzskUzgQng3KoMY3Ho6bCxm2At00+Jmfz/bLknj/KB8qie0ionuvOkSFSc1rqPtijVN4L5EJRS1y8LWMGxJTsxAnqJdlLynFx7zi3n/C3Aywwhtz2ijyQNFLgZtnbhVIZYDnf8GwLsWPJjbEeE1JoDAO4wNtT4DuV5mHAdWqY8CgYEAvH9GuQgc+7un90kAFY9nyvlkD/D2cRcfF0Z+FPoj3/k3GS6pXWfnrORgkiGwyqm1e83Tx8RPYMtkRgAGy2mW4ibj7jbOFJYQNBZiML7DAtYuwDDdILm1d4F3840/QHYdtXdWHIryKmdthjmA/Bt1u0MSMmhaGVfHFdYUF2mNjVcCgYEA6mDAZN3fN0tCqakf0h6wk8E6AbqIySOkuW5ECa0JbnrYaRCK7xgva0sspsjcYDZAzX9fKv/xdanjtjE+jo2sjoBKRtCQYFH58dBuNoKvGEoL2ctbmEN7/QZW0oyF/ijEWq7Qie8AnQ3eiq3GvFQnFlEnxtidlmmXsQNop++SwScCgYBQCHJMyccUkx7D/fjNLrBRHAaCRjs81SZcSY/q9DIbPMNKK+e5Qw6499aQ9UENK3Vk9YWAAjf5zyHqHsTDxTdNGloYoKhrUTPcCczzCWvfXnVHIPgilvcXoJ7/h+9dPUlr7Rlg0RX1LyjvnqbHZBlewyGMyYXH0N80xEqPjj+NzQKBgQCyhmWVWUiZNNMV5aWcHy8XFoXuvLIFWbA2WvPoPG+Xia+5BO2ytTI0VJKBY5ACaEofWsy5R2/L6cJhYeSTGe9z0K6Wg96NsxV4BSawp+jseV7oi1HdpTMB4dGph0DJUFMJZ1Lm0s7r5aZ5pkZ6+JYGry1EGmjmR+xaVHodd2LNpw==")

	pem_bytes := []byte(`-----BEGIN PRIVATE KEY-----
MIIEpAIBAAKCAQEAtrCYn039gp/IjLZsNl64QjHjPfAklyYZyIPSqlPNmColRMOAb2rbnLASRpP1
VgT7YzA4JgJ1f/fhGsSBexpIi2BOZdwDexBtmfe9dFGzbWhpqAxzWnZazLde+BGOs6BGk0v1B0cW
Uqlv6wgSSo57Xu7xL56a34gDsBi1qoXnu4f1CzrvviRsNCgDDurNsAtkjLzoPuzHri6sThsQ7P3a
mb3zyG5xVxSGZRFKgPNoiiZpBpXPoEwMrHQRE8rmsmgdz+E4YL1xuD+ICQxCCTBOJwUuDzPt5wr7
93Pxgloqh0p3yPvOShmbMAxUtLiGgcZNqxy49ddG89egVyGxRJpimQIDAQABAoIBAEfGUfAkn/j1
9cDy2sjxpcq79t+avYV0vqR8xgONMTUbOdEuTgN4JBgHRObdsoG9K1bo1uZ4CNnh9Vqi4YwP43h+
uc5jBisPZUAciR5uCuRtJTWUzq032qybToB/xWTlD1VHflkBoM+RKhtY7HbGS8ocbj2bPpWbxnck
/hqkyUpvkFkO0/ngHr6V44pxEK7sm53abiey4jtAQwJcLgS3wLcbSbVGsfRI1srq1I1s54EKzZfJ
xqRynuMiaKDPGHrUHEcNCQcWS3k4cU1sZF5jMk17f97SzwC8Iz0Kfd7zzw8IiGmvX7sYHJL0mPwq
AF+rSlVwZs+Fj/DDcFcBHvpSlBECgYEA+BzskUzgQng3KoMY3Ho6bCxm2At00+Jmfz/bLknj/KB8
qie0ionuvOkSFSc1rqPtijVN4L5EJRS1y8LWMGxJTsxAnqJdlLynFx7zi3n/C3Aywwhtz2ijyQNF
LgZtnbhVIZYDnf8GwLsWPJjbEeE1JoDAO4wNtT4DuV5mHAdWqY8CgYEAvH9GuQgc+7un90kAFY9n
yvlkD/D2cRcfF0Z+FPoj3/k3GS6pXWfnrORgkiGwyqm1e83Tx8RPYMtkRgAGy2mW4ibj7jbOFJYQ
NBZiML7DAtYuwDDdILm1d4F3840/QHYdtXdWHIryKmdthjmA/Bt1u0MSMmhaGVfHFdYUF2mNjVcC
gYEA6mDAZN3fN0tCqakf0h6wk8E6AbqIySOkuW5ECa0JbnrYaRCK7xgva0sspsjcYDZAzX9fKv/x
danjtjE+jo2sjoBKRtCQYFH58dBuNoKvGEoL2ctbmEN7/QZW0oyF/ijEWq7Qie8AnQ3eiq3GvFQn
FlEnxtidlmmXsQNop++SwScCgYBQCHJMyccUkx7D/fjNLrBRHAaCRjs81SZcSY/q9DIbPMNKK+e5
Qw6499aQ9UENK3Vk9YWAAjf5zyHqHsTDxTdNGloYoKhrUTPcCczzCWvfXnVHIPgilvcXoJ7/h+9d
PUlr7Rlg0RX1LyjvnqbHZBlewyGMyYXH0N80xEqPjj+NzQKBgQCyhmWVWUiZNNMV5aWcHy8XFoXu
vLIFWbA2WvPoPG+Xia+5BO2ytTI0VJKBY5ACaEofWsy5R2/L6cJhYeSTGe9z0K6Wg96NsxV4BSaw
p+jseV7oi1HdpTMB4dGph0DJUFMJZ1Lm0s7r5aZ5pkZ6+JYGry1EGmjmR+xaVHodd2LNpw==
-----END PRIVATE KEY-----`)

	block, left := pem.Decode(pem_bytes)
	is.Empty(left)
	is.NotNil(block)

	bb, _ := hex2block(raw_bytes)
	is.Equal(*block, *bb)

	privk, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	is.NotNil(privk)
	is.Nil(err)

	input := []byte("a=b")

	h := sha256.New()
	is.Equal(32, h.Size())
	h.Write(input)

	hashed := h.Sum(nil)
	is.Equal(32, len(hashed))
	is.Equal("42144f3939c3ffbbf0bf8b1f12affb5c23a4c5bd41e0ff672d54a5754f062058",
		fmt.Sprintf("%x", hashed),
	)

	signed, ers := rsa.SignPKCS1v15(rand.Reader, privk, crypto.SHA256, hashed)
	is.Nil(ers)
	_ = signed

	erv := rsa.VerifyPKCS1v15(&privk.PublicKey, crypto.SHA256, hashed, signed)
	is.Nil(erv)
}

func TestVerify(t *testing.T) {
	is := assert.New(t)

	raw_bytes := []byte(`MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCEHnXBMcDV8E8J6TIf/c+vrMFIWIuDeCyXdjqScJ5Oxt6/RcsZBvjGwsF+0d5XLx7Zk312B+9tuQTtPeg529Sa3auzMgH9X/00Pisxgl86RMD2sArxn6tvpaQF1fCywgry6I69aNaenulRYhu8lzG7KKqapTDeZgBHDqs2Mms7EidSCSigfZllg1dHqDzyT1elQ/ZNByS1oRjZEt1n/hE60pjsZQ3PhTyotf3aW3WADdLAf7qbI5K3XUaqoiRL62Db9NU/R5D+ZrqQ7hiWWypSHvJ9KjHDOr4aHOxij2W5e2WAk55oSdRKXErTjVicpnOm2790Djtb1EMFyI1RT0ndAgMBAAECggEAbjtb1E1GrzlJOOOwRrDlz5U7zrjR7mceDWE/jV8ZNnEG+F+rDL6cYnmsJ7vC3ssZ2j8MtqX4RnvQeIDmeR/JS00YLPLUZirof+Y+85frDBrBRRGsj9zAlO6G47eUlBECQZl3PuFx7/Z2hMhui/M6MwXDEjQxid1g7eh3QUjf3vANBYdlw1QmUlybyrkIIUWjNmxQYkrgdl2P7Fu/HL7BXQcP5oNJaGfgMMTNDeIT70ok60rdLS23Gkeiom4XQm8/PiRneeLQECnxpDOTMs32K+Wm7yhv7FL+0Yuf35FTEnkJIy1CD9aXhvUJR7pCqXYjIBSth0qtQnmWcnPtoKZtoQKBgQD6LbqdIJUorPQyYB8hP8/Me2eavl9PWwV/rJmXEQBYWDmRj/gXo8BO+ndv21BjFK1uQhyrGopnP2xxXNpheKafhA9PjGjZDcggqch8R+ifB8gpCsgFw3pNYW4U5SNPvPRLUYQVdlIG9hdA6B9+6vuuwzkyWpwIwXbU2bmnsdcyEwKBgQCHMXhUF40oEQzGQrbTlkSk/Or4bBuETAwedupoa8AxlSPscVj/tFvnYqNkTA2l1UTOdr9O6Ygbqa+aMPl+Doc6jsABFMPHnow9eXTURU2cD6ru9BcxVSvYL7OEU5SGLoKNrFC345Uc7lXRMQo/jV7AvXhQXg+1hN8hVZ8O4EiSTwKBgCR0sXLgIpwwx8zncOHZeKBlgy1rfFwF+YEnV6JJ2fEFui3Z+t8G/6kCmpD0NnyZsMQWYjMUxQJSnazPSQtXF4C7L7f5z/WBKp6H3y0tFVrHOYWxioA8gf/wqKfm1AR0lmy7TjIKcd2N0smkiaJm/5Hx5M3PolksR/KwX3tuUNt9AoGAbNnA93wq9CqeLXeDuuLPjEPzcGei1CdizpiSbdbr3UAmt3Yf4Wo3YRsDUXsGthH8H3xu1jujkhpSwARUrVFHQjezkmtEoxId+lUzYsIWFeRrjY/MqLTZ42usz4t4F32VMjqelyDPa4beY9tnU/ogY3FqUNMbNNyxxyYoNhMRe3MCgYEAm26p6SFNygxseGFlkwbWcRUgtol2w8R8MP0YHC1vtsbtT+xAEt9REPsrlWzATVLIfLhef4B63ESJYgY0tQUe+AOeAtxJoA8SNMzII+1DkfyNshNaFNa32ENw7Eal+4MLAVHl8pgpIeXgeo3toA3h72kh1k+INdJKFacEepxp5XA=`)
	block, _ := hex2block(raw_bytes)
	ka, erp := x509.ParsePKCS8PrivateKey(block.Bytes)
	is.Nil(erp)
	privk, ok := ka.(*rsa.PrivateKey)
	is.True(ok)
	is.NotNil(privk)

	input := []byte("a=b")

	h := sha256.New()
	h.Write(input)
	hashed := h.Sum(nil)
	is.Equal("42144f3939c3ffbbf0bf8b1f12affb5c23a4c5bd41e0ff672d54a5754f062058",
		fmt.Sprintf("%x", hashed),
	)

	tool_signed, erd := base64.StdEncoding.DecodeString(
		`Uci+76ETZM5scXcAFtULpocPOnuxLPbVfq8g6nirYkbthLGD/yichOAyF6j0l3TBHudJcEhuydsM978F9HneekZt/YmUALRPxDX7q0aR8SDZcT4dcD4TpHBSmn7qLFrbVGgsIRwa782JNqAyzzoRup1mAcvp0vEk9t7cudoMmt8LFkahpVoxq4PKVpYuB7wJzqTAtVjWQapb016ncQfihqmwOtHOIjrUNY9xaoNmBsKVKM9zKpHFLxjpMv2I/jXIQzSCDaf3+fF4jXB96c6HrQ7fbU3m6vEvmEWrHqGzph6ZORRtUAXzGQ2+ze972WqHAeiXRHfVtcPWaKzh0QRcGw==`,
	)
	is.Nil(erd)
	is.Equal(256, len(tool_signed))

	// verify with private key's public key
	erv := rsa.VerifyPKCS1v15(&privk.PublicKey, crypto.SHA256, hashed, tool_signed)
	is.Nil(erv)

	// with standalone public key
	block_public, left := hex2block(
		[]byte(`MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAhB51wTHA1fBPCekyH/3Pr6zBSFiLg3gsl3Y6knCeTsbev0XLGQb4xsLBftHeVy8e2ZN9dgfvbbkE7T3oOdvUmt2rszIB/V/9ND4rMYJfOkTA9rAK8Z+rb6WkBdXwssIK8uiOvWjWnp7pUWIbvJcxuyiqmqUw3mYARw6rNjJrOxInUgkooH2ZZYNXR6g88k9XpUP2TQcktaEY2RLdZ/4ROtKY7GUNz4U8qLX92lt1gA3SwH+6myOSt11GqqIkS+tg2/TVP0eQ/ma6kO4YllsqUh7yfSoxwzq+GhzsYo9luXtlgJOeaEnUSlxK041YnKZzptu/dA47W9RDBciNUU9J3QIDAQAB`),
		"PUBLIC KEY")
	is.Empty(left)
	pa, err := x509.ParsePKIXPublicKey(block_public.Bytes)
	is.Nil(err)
	public_key, ok := pa.(*rsa.PublicKey)
	is.True(ok)

	erv2 := rsa.VerifyPKCS1v15(public_key, crypto.SHA256, hashed, tool_signed)
	is.Nil(erv2)
}

func TestClient(t *testing.T) {
	ResponseArgs := []Arg{
		{string: "format", max: 40, opt: false, def: "JSON"},
		{string: "code", opt: false},
		{string: "msg", opt: false},
		{string: "sub_code", opt: false},
		{string: "sub_msg", opt: false},
		{string: "sign", opt: false},
	}
	_ = ResponseArgs
}

// not fake site
func TestAMethod(t *testing.T) {
	is := assert.New(t)

	// copy from https://github.com/smartwalle/alipay
	// examples/main.go
	pr, err := NewSpare("9021000122689420",
		"MIIEpAIBAAKCAQEAtrCYn039gp/IjLZsNl64QjHjPfAklyYZyIPSqlPNmColRMOAb2rbnLASRpP1VgT7YzA4JgJ1f/fhGsSBexpIi2BOZdwDexBtmfe9dFGzbWhpqAxzWnZazLde+BGOs6BGk0v1B0cWUqlv6wgSSo57Xu7xL56a34gDsBi1qoXnu4f1CzrvviRsNCgDDurNsAtkjLzoPuzHri6sThsQ7P3amb3zyG5xVxSGZRFKgPNoiiZpBpXPoEwMrHQRE8rmsmgdz+E4YL1xuD+ICQxCCTBOJwUuDzPt5wr793Pxgloqh0p3yPvOShmbMAxUtLiGgcZNqxy49ddG89egVyGxRJpimQIDAQABAoIBAEfGUfAkn/j19cDy2sjxpcq79t+avYV0vqR8xgONMTUbOdEuTgN4JBgHRObdsoG9K1bo1uZ4CNnh9Vqi4YwP43h+uc5jBisPZUAciR5uCuRtJTWUzq032qybToB/xWTlD1VHflkBoM+RKhtY7HbGS8ocbj2bPpWbxnck/hqkyUpvkFkO0/ngHr6V44pxEK7sm53abiey4jtAQwJcLgS3wLcbSbVGsfRI1srq1I1s54EKzZfJxqRynuMiaKDPGHrUHEcNCQcWS3k4cU1sZF5jMk17f97SzwC8Iz0Kfd7zzw8IiGmvX7sYHJL0mPwqAF+rSlVwZs+Fj/DDcFcBHvpSlBECgYEA+BzskUzgQng3KoMY3Ho6bCxm2At00+Jmfz/bLknj/KB8qie0ionuvOkSFSc1rqPtijVN4L5EJRS1y8LWMGxJTsxAnqJdlLynFx7zi3n/C3Aywwhtz2ijyQNFLgZtnbhVIZYDnf8GwLsWPJjbEeE1JoDAO4wNtT4DuV5mHAdWqY8CgYEAvH9GuQgc+7un90kAFY9nyvlkD/D2cRcfF0Z+FPoj3/k3GS6pXWfnrORgkiGwyqm1e83Tx8RPYMtkRgAGy2mW4ibj7jbOFJYQNBZiML7DAtYuwDDdILm1d4F3840/QHYdtXdWHIryKmdthjmA/Bt1u0MSMmhaGVfHFdYUF2mNjVcCgYEA6mDAZN3fN0tCqakf0h6wk8E6AbqIySOkuW5ECa0JbnrYaRCK7xgva0sspsjcYDZAzX9fKv/xdanjtjE+jo2sjoBKRtCQYFH58dBuNoKvGEoL2ctbmEN7/QZW0oyF/ijEWq7Qie8AnQ3eiq3GvFQnFlEnxtidlmmXsQNop++SwScCgYBQCHJMyccUkx7D/fjNLrBRHAaCRjs81SZcSY/q9DIbPMNKK+e5Qw6499aQ9UENK3Vk9YWAAjf5zyHqHsTDxTdNGloYoKhrUTPcCczzCWvfXnVHIPgilvcXoJ7/h+9dPUlr7Rlg0RX1LyjvnqbHZBlewyGMyYXH0N80xEqPjj+NzQKBgQCyhmWVWUiZNNMV5aWcHy8XFoXuvLIFWbA2WvPoPG+Xia+5BO2ytTI0VJKBY5ACaEofWsy5R2/L6cJhYeSTGe9z0K6Wg96NsxV4BSawp+jseV7oi1HdpTMB4dGph0DJUFMJZ1Lm0s7r5aZ5pkZ6+JYGry1EGmjmR+xaVHodd2LNpw==",
		`-----BEGIN CERTIFICATE-----
MIIDmTCCAoGgAwIBAgIQICMGFE/GVT29GaZP4DEOYzANBgkqhkiG9w0BAQsFADCBkTELMAkGA1UE
BhMCQ04xGzAZBgNVBAoMEkFudCBGaW5hbmNpYWwgdGVzdDElMCMGA1UECwwcQ2VydGlmaWNhdGlv
biBBdXRob3JpdHkgdGVzdDE+MDwGA1UEAww1QW50IEZpbmFuY2lhbCBDZXJ0aWZpY2F0aW9uIEF1
dGhvcml0eSBDbGFzcyAyIFIxIHRlc3QwHhcNMjMwNjE0MDgxNDUyWhcNMjQwNjE4MDgxNDUyWjBr
MQswCQYDVQQGEwJDTjEfMB0GA1UECgwWZGRzdW12NTQyMUBzYW5kYm94LmNvbTEPMA0GA1UECwwG
QWxpcGF5MSowKAYDVQQDDCEyMDg4NzIxMDA0MTEzNTkzLTkwMjEwMDAxMjI2ODk0MjAwggEiMA0G
CSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC2sJifTf2Cn8iMtmw2XrhCMeM98CSXJhnIg9KqU82Y
KiVEw4BvatucsBJGk/VWBPtjMDgmAnV/9+EaxIF7GkiLYE5l3AN7EG2Z9710UbNtaGmoDHNadlrM
t174EY6zoEaTS/UHRxZSqW/rCBJKjnte7vEvnprfiAOwGLWqhee7h/ULOu++JGw0KAMO6s2wC2SM
vOg+7MeuLqxOGxDs/dqZvfPIbnFXFIZlEUqA82iKJmkGlc+gTAysdBETyuayaB3P4ThgvXG4P4gJ
DEIJME4nBS4PM+3nCvv3c/GCWiqHSnfI+85KGZswDFS0uIaBxk2rHLj110bz16BXIbFEmmKZAgMB
AAGjEjAQMA4GA1UdDwEB/wQEAwIE8DANBgkqhkiG9w0BAQsFAAOCAQEAeyLzHfHRnZ7D3dHFJg9D
P/85ldjMIuJ4JRwVVFfcRBg496RlAs+F4rK0lWiykkBv1LtLINt/TI6wtqmpSy8Coi7xE2op+hKQ
B6ndf8Z1boE+Yjdi66uPSHNfgb5KYZeq+LB9QTDmKPCeF8eah789S0qpJ9YQkdZIl+khf7xYT+0a
ERQSb1ti/q2XSeikpHm8vWj0Jzsl4EZnZ22omcHii0iXeyzbHwaHAR90NVVko1Zy6BapLp0raX7x
a7xuuqW6GKRRkKT4w6mUl3nZ4lXP92+UHpcip/enwprlVdPdLbcJq0sxB97PEKfP6SAaCTji1Tdt
PzyPWSx9O07vRhN84Q==
-----END CERTIFICATE-----`,
		"iotxR/d99T9Awom/UaSqiQ==",
	)
	is.Nil(err)

	// - test encrypt
	plain := []byte(`{"subject":"支付测试:1538","out_trade_no":"1538","total_amount":"10.00","product_code":"FAST_INSTANT_TRADE_PAY"}`)
	dest, err := hex.DecodeString(`7100fd1b58e1c038b6085b97c0f080630555dbfa454cada3f82e851e2df3bcdbc413afcde181e13aacd70a0a2b3f6009824b63b0667ea68e7e924437687bd5fd5062d2fefc002eb50837bb633840fb53cf7f173e9557055dcda1647aff43dbecc491b7c11291d5f71ad6ef770dc10ef163e49edc0ac07d7cbb3ed03365b5585a`)
	is.Nil(err)

	ciph_bs := pr.encrypt(plain)
	is.Equal(dest, ciph_bs)
	is.Equal(fmt.Sprintf("%x", ciph_bs),
		hex.EncodeToString(dest),
	)

	// - alisn
	is.Equal("deb4cd7ff642ef1256f9ba63f63cf7b0", pr.app_cert_sn)
	// 687b59193f3f462dd5336e5abf83c5d8_02941eef3187dddf3d3b83462e1dfcf6
	// invalid-alipay-root-cert-sn
	is.Equal("687b59193f3f462dd5336e5abf83c5d8_8af620707e5ddd8c7e76747e86a604dc_02941eef3187dddf3d3b83462e1dfcf6", ali_root_sn())

	// - sign
	m := map[string]string{
		"charset":             "utf-8",
		"timestamp":           "2023-07-29 23:26:48",
		"app_cert_sn":         "deb4cd7ff642ef1256f9ba63f63cf7b0",
		"alipay_root_cert_sn": "687b59193f3f462dd5336e5abf83c5d8_02941eef3187dddf3d3b83462e1dfcf6",
		"encrypt_type":        "AES",
		"notify_url":          "/alipay/notify",
		"return_url":          "/alipay/callback",
		"app_id":              "9021000122689420",
		"method":              "alipay.trade.page.pay",
		"format":              "JSON",
		"sign_type":           "RSA2",
		"version":             "1.0",
		"biz_content":         "cQD9G1jhwDi2CFuXwPCAYwVV2/pFTK2j+C6FHi3zvNvEE6/N4YHhOqzXCgorP2AJgktjsGZ+po5+kkQ3aHvV/VBi0v78AC61CDe7YzhA+1PPfxc+lVcFXc2hZHr/Q9vsxJG3wRKR1fca1u93DcEO8WPkntwKwH18uz7QM2W1WFo=",
	}

	joined_dest := "alipay_root_cert_sn=687b59193f3f462dd5336e5abf83c5d8_02941eef3187dddf3d3b83462e1dfcf6&app_cert_sn=deb4cd7ff642ef1256f9ba63f63cf7b0&app_id=9021000122689420&biz_content=cQD9G1jhwDi2CFuXwPCAYwVV2/pFTK2j+C6FHi3zvNvEE6/N4YHhOqzXCgorP2AJgktjsGZ+po5+kkQ3aHvV/VBi0v78AC61CDe7YzhA+1PPfxc+lVcFXc2hZHr/Q9vsxJG3wRKR1fca1u93DcEO8WPkntwKwH18uz7QM2W1WFo=&charset=utf-8&encrypt_type=AES&format=JSON&method=alipay.trade.page.pay&notify_url=/alipay/notify&return_url=/alipay/callback&sign_type=RSA2&timestamp=2023-07-29 23:26:48&version=1.0"
	to_sign := stupid_joint(m)
	is.Equal(joined_dest, to_sign)

	signed := pr.Sign(to_sign)
	signed_dest := "D1cJ1DtA7PohcNkNeeE+lk3xDvultFRd4plJUO9hWuSbS4H1pnsmBcnkUvl86jYgmbDr9zEGxHcCdQ7P6adBHsK2U7jEaJ1eZZv/vCrdh4w3v4WeqGuh43sB5ar2TFCVcEkKvQdpb35IBgAYmfTuQ6ZWrouBv96xUfJqdqU8hiC1ZCY0lPtZDyj8QxJ7NZ0E7uzFcSl85f9YWiu1w00hsZVh50ody6aDOznXDYWluN1Q7Wc2YTMV9pvcTyhEZMI/lDpasObJgx1JGBRT0Uwu34l9hH8v+RGojmvCYoSgqejjaxL/JHayHsPj/BGwNBNiArOy9DBKhZWijQv+lhc4NA=="
	is.Equal(signed_dest, signed)

	req := pr.BuildRequest("alipay.trade.page.pay", map[string]string{
		"subject":      "支付测试",
		"out_trade_no": "12312311",
		"total_amount": "10.00",
		"product_code": "FAST_INSTANT_TRADE_PAY",
	})
	log.Print(req.URL.String())
}
