// Most simply alipay SDK implement in Go
//
//	pr, err := NewSpear("appid", "app_private_key", "app_public_key", "aeskey")
//	pr.Do("alipay.trade.page.pay", map[string]string{
//	    "subject":      "支付测试",
//	    "out_trade_no": "12312311",
//	    "total_amount": "10.00",
//	    "product_code": "FAST_INSTANT_TRADE_PAY",
//	})
package alipay

import (
	"bytes"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/samber/lo"
)

type Arg struct {
	string        // treat Arg as string
	max    int    // max size, not used
	opt    bool   // optional?
	def    string // default value
	val    string // custom value
}

func DefArg(name, val string) Arg {
	return Arg{string: name, val: val}
}

var CommonArgs = []Arg{
	{string: "format", max: 40, opt: false, def: "JSON"},
	{string: "charset", max: 10, opt: false, def: "utf-8"},
	{string: "sign_type", max: 10, opt: false, def: "RSA2"},
	{string: "version", max: 3, opt: false, def: "1.0"},
	{string: "encrypt_type", max: 3, opt: false, def: "AES"},
	{string: "app_id", max: 32, opt: false},
	{string: "method", max: 128, opt: false},
	{string: "sign", max: 344, opt: false},
	{string: "timestamp", max: 19, opt: false},
	{string: "app_auth_token", max: 40, opt: true},
	{string: "biz_content", max: 0, opt: false},
	{string: "return_url", max: 0, opt: false},
	{string: "notify_url", max: 0, opt: false},
}

// alipay.Client
type Spear struct {
	site_url string
	appid    string
	//                                  //  desc             | filename                            | name in doc
	privk               *rsa.PrivateKey   // app private key | 应用私钥RSA2048-敏感数据，请妥善保管.txt | 应用私钥 RSA 2048
	app_cert_sn         string            // alisn of        | appCertPublicKey_.crt               | 应用公钥证书's alisn
	app_cert            *x509.Certificate //                 | appCertPublicKey_.crt               | 应用公钥证书
	alipay_root_cert_sn string            // alisn of        | alipayRootCert.crt                  | 支付宝根证书
	alipay_public_certs []*x509.Certificate
	aes_key             []byte
	client              *http.Client
}

func NewSpear(appid string,
	app_private_key string,
	app_public_key string,
	aes_key string) (*Spear, error) {
	// private key
	block, _ := hex2block([]byte(app_private_key))
	var privk *rsa.PrivateKey
	pa, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		pa, err = x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
	}

	privk, ok := pa.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("not rsa.PrivateKey")
	}

	// load app public cert, generate `alisn`
	pub_pem, _ := pem.Decode([]byte(app_public_key))
	cert, err := x509.ParseCertificate(pub_pem.Bytes)
	if err != nil {
		return nil, err
	}
	app_cert_sn := alisn(cert)

	//
	pubs := []*x509.Certificate{}
	if true {
		rest := aliPublicPemForRSA2
		for {
			block, left := pem.Decode(rest)
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				log.Printf("parse failed %s", err)
			}
			if cert != nil {
				pubs = append(pubs, cert)
			}

			if len(left) == 0 {
				break
			}
			rest = left

		}
	}
	_ = pubs

	// Sadly this not worked: invalid-alipay-root-cert-sn
	// 687b59193f3f462dd5336e5abf83c5d8_8af620707e5ddd8c7e76747e86a604dc_02941eef3187dddf3d3b83462e1dfcf6
	// alipay_root_cert_sn := ali_root_sn()
	// copy from https://github.com/smartwalle/alipay
	alipay_root_cert_sn := "687b59193f3f462dd5336e5abf83c5d8_02941eef3187dddf3d3b83462e1dfcf6"

	// aes, CAUTION: use PKCS7Padding
	akb, err := base64.StdEncoding.DecodeString(aes_key)
	if err != nil {
		return nil, err
	}

	return &Spear{
		site_url:            "https://openapi.alipay.com/gateway.do",
		appid:               appid,
		aes_key:             akb,
		app_cert_sn:         app_cert_sn,
		app_cert:            cert,
		alipay_root_cert_sn: alipay_root_cert_sn,
		alipay_public_certs: pubs,
		privk:               privk,
		client:              http.DefaultClient,
	}, nil
}

func NewSandboxSpear(appid string,
	app_private_key string,
	app_public_key string,
	aes_key string) (*Spear, error) {
	if !strings.HasPrefix(appid, "90") {
		panic("sandbox appid should start with 90")
	}

	pr, err := NewSpear(appid, app_private_key, app_public_key, aes_key)
	if pr != nil {
		pr.site_url = "https://openapi-sandbox.dl.alipaydev.com/gateway.do"
	}
	return pr, err
}

// Convert raw hex string to pem block, like
//
//	-----BEGIN PRIVATE KEY-----
//	MIIDmTCCAoGgAwIBAgIQICMGFE/GVT29GaZP4DEOYzANBgkqhkiG9w0BAQsFADCBkTELMAkGA1UE
//	...
//	-----END PRIVATE KEY-----
func hex2block(bs []byte, typos ...string) (*pem.Block, []byte) {
	typo := "PRIVATE KEY"
	if len(typos) > 0 {
		typo = typos[0]
	}

	lines := [][]byte{
		[]byte(fmt.Sprintf("-----BEGIN %s-----", typo)),
	}

	len := len(bs)

	for i := 0; i <= len/76; i++ {
		tail := (i + 1) * 76
		if tail > len { // min(tail, len)
			tail = len
		}
		// fmt.Printf("%d - %d\n", i*76, tail)
		lines = append(lines, bs[i*76:tail])
	}

	lines = append(lines, []byte(
		fmt.Sprintf("-----END %s-----", typo),
	))

	return pem.Decode(bytes.Join(lines, []byte("\n")))
}

// generate shit `sn`, md5(issuer + serial_number)
func alisn(certs ...*x509.Certificate) string {
	return strings.Join(
		lo.Map(certs, func(cert *x509.Certificate, _ int) string {
			bs := md5.Sum([]byte(cert.Issuer.String() + cert.SerialNumber.String()))
			return fmt.Sprintf("%x", bs) // hex encode
		}),
		"_")
}

// alisn for alipayRootCert.crt 支付宝根证书
func ali_root_sn() string {
	certs := []*x509.Certificate{}
	rest := aliRootCert
	for {
		block, left := pem.Decode(rest)
		if block != nil {
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				log.Printf("parse failed %s", err)
			}
			if cert != nil {
				certs = append(certs, cert)
			}
		}

		// no more block
		if len(left) == 0 {
			break
		}

		rest = left
	}

	return alisn(certs...)
}

// sign with private key and base64, see [doc](https://opendocs.alipay.com/common/057k53?pathHash=7b14a0af)
func (pr *Spear) Sign(s string) string {
	h := sha256.New()
	h.Write([]byte(s))
	hashed := h.Sum(nil)

	signed, ers := rsa.SignPKCS1v15(rand.Reader, pr.privk, crypto.SHA256, hashed)
	if ers != nil {
		log.Fatalf("sign failed %s", ers)
	}

	return base64.StdEncoding.EncodeToString(signed)
}

func (pr *Spear) Verify(s, sign string) error {
	h := sha256.New()
	h.Write([]byte(s))
	hashed := h.Sum(nil)

	signed_bs, err := base64.StdEncoding.DecodeString(sign)
	if err != nil {
		return err
	}

	for _, cert := range pr.alipay_public_certs {
		if err := rsa.VerifyPKCS1v15(cert.PublicKey.(*rsa.PublicKey), crypto.SHA256, hashed, signed_bs); err == nil {
			return nil
		}
	}

	if err := rsa.VerifyPKCS1v15(pr.app_cert.PublicKey.(*rsa.PublicKey), crypto.SHA256, hashed, signed_bs); err == nil {
		return nil
	}

	if err := rsa.VerifyPKCS1v15(&pr.privk.PublicKey, crypto.SHA256, hashed, signed_bs); err == nil {
		return nil
	}

	return rsa.ErrVerification
}

// should not use url.Values.Encode
func stupid_joint(m map[string]string) string {
	ks := lo.Keys(m)
	sort.Strings(ks)

	return strings.Join(lo.Map(ks, func(k string, _ int) string {
		return k + "=" + m[k]
	}), "&")
}

// call url.Values.Encode for map
func encode(m map[string]string) string {
	vs := lo.MapEntries(m, func(k, v string) (string, []string) {
		return k, []string{v}
	})
	return url.Values(vs).Encode()
}

func PKCS7Padding(b []byte, block_size int) []byte {
	pad_size := block_size - len(b)%block_size
	pad := bytes.Repeat([]byte{byte(pad_size)}, pad_size)
	return append(b, pad...)
}

func PKCS7UnPadding(b []byte) []byte {
	size := len(b)
	unpad_size := int(b[size-1])
	return b[:(size - unpad_size)]
}

// aes encrypt with zero-filled iv
func (pr *Spear) encrypt(src []byte) []byte {
	block, err := aes.NewCipher(pr.aes_key)
	if err != nil {
		panic(err)
	}

	bs := PKCS7Padding(src, block.BlockSize())
	iv := make([]byte, block.BlockSize()) // CAUTION: random filled iv not worked
	rs := make([]byte, len(bs))

	cipher.NewCBCEncrypter(block, iv).CryptBlocks(rs, bs)
	return rs
}

// Only [biz_content] args, not include any common args
func (pr *Spear) BuildRequest(api_method string, biz_args map[string]string, override_common_args ...Arg) *http.Request {
	// 1 encrypt biz_content, see [doc](https://opendocs.alipay.com/common/02kdnc)
	bs, _ := json.Marshal(biz_args)
	enc_bs := pr.encrypt(bs)

	// 2 build the args with common args
	args := map[string]string{
		"app_id":              pr.appid,
		"method":              api_method,
		"timestamp":           time.Now().Format("2006-01-02 15:04:05"),
		"biz_content":         base64.StdEncoding.EncodeToString(enc_bs), // set biz_content here
		"app_cert_sn":         pr.app_cert_sn,
		"alipay_root_cert_sn": pr.alipay_root_cert_sn, // for gateway error miss_alipay_root_cert_sn
	}

	for i := 0; i < len(CommonArgs); i++ {
		a := CommonArgs[i]
		if !a.opt && a.def != "" {
			args[a.string] = a.def
		}
	}

	// 3 additional common args
	for i := 0; i < len(override_common_args); i++ {
		a := override_common_args[i]
		if a.val != "" {
			args[a.string] = a.val
		}
	}

	// 3 sign
	to_sign := stupid_joint(args)
	args["sign"] = pr.Sign(to_sign)

	// log.Printf("biz_content: %x\nenc: %x\nbase64: %s", bs, enc_bs, args["biz_content"])
	// log.Printf("sign %s \nto %s", to_sign, args["sign"])

	uri, erp := url.Parse(pr.site_url + "?" + encode(args))
	if erp != nil {
		log.Fatalf("make url failed %s", erp)
		return nil
	}

	return &http.Request{
		Method: "GET",
		URL:    uri,
		Header: http.Header{
			"content-type": []string{"application/x-www-form-urlencoded;charset=utf-8"},
			// "cache-control": "no-cache",
			// "connection": "keep-alive",
			// JOKE: "user-agent": []string{"stupid-alipay/1.0"},
		},
	}
}

func (pr *Spear) Do(api_method string, biz_args map[string]string, override_common_args ...Arg) (*http.Response, error) {
	req := pr.BuildRequest(api_method, biz_args)
	if req == nil {
		return nil, errors.New("build request failed")
	}

	resp, err := pr.client.Do(req)
	if false {
		for k, v := range resp.Header {
			log.Printf("%s=%s", k, v[0])
		}
		if bs, err := io.ReadAll(resp.Body); err == nil {
			log.Print(string(bs))
		}
	}

	return resp, err
}

var CommonResponseArg = []Arg{
	{string: "code", opt: false},
	{string: "msg", opt: false},
	{string: "sub_code", opt: true},
	{string: "sub_msg", opt: true},
	{string: "sign", opt: false},
}

func (pr *Spear) VerifyRequest(r *http.Request) bool {
	plain_map := lo.MapValues(r.URL.Query(), func(v []string, k string) string {
		return v[0]
	})

	sign := plain_map["sign"]
	delete(plain_map, "sign")

	err := pr.Verify(stupid_joint(plain_map), sign)
	if err != nil {
		log.Printf("verify failed %s", err)
	}
	return err == nil
}
