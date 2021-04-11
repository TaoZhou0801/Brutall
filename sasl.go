// sasl.go implements PLAIN, CRAM & DIGEST authentication (SASLprep unimplemented).
//
// Reference:
//		RFC 2195 - SASL CRAM-MD5
//		RFC 2831 - SASL DIGEST
//		RFC 4422 - SASL STANDARD
//		RFC 4616 - SASL PLAIN
//
// TODO:
//		qop: auth-conf

package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/md5"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"hash"
	"strings"
)

var b64 = base64.StdEncoding

// message = [authzid] UTF8NUL authcid UTF8NUL passwd
func SaslPlain(authzid, authcid, passwd string) []byte {
	buf := make([]byte, len(authzid)+len(authcid)+len(passwd)+2)
	i := copy(buf, authzid)
	i += copy(buf[i+1:], authcid) + 1
	copy(buf[i+1:], passwd)

	return buf
}

// message = username <SP> hmac(hash, password, challenge)
func SaslCram(challenge []byte, h func() hash.Hash, user, pass string) []byte {
	hash := hmac.New(h, []byte(pass))
	hash.Write([]byte(challenge))

	buf := make([]byte, len(user)+hex.EncodedLen(hash.Size())+1)
	i := copy(buf, user)
	buf[i] = ' '
	i = hex.Encode(buf[i+1:], hash.Sum(nil))

	return buf
}

// minimal implementation of sasl digest-md5 authentication
func SaslDigest(message []byte, service, host, user, pass string) ([]byte, error) {
	str := string(message)
	// server nonce
	i := strings.Index(str, "nonce=\"")
	if i == -1 {
		return nil, errors.New("no server nonce")
	}
	snonce := message[i+7 : bytes.IndexByte(message[i+7:], '"')+i+7]

	// quality of protection
	var qop string
	i = strings.Index(str, "qop=")
	if i != -1 {
		tmp := string(message[i+5 : bytes.IndexByte(message[i+5:], '"')+i+5])
		if strings.HasSuffix(tmp, "auth") || strings.Contains(tmp, "auth,") {
			qop = "auth"
		} else if strings.Contains(tmp, "auth-int") {
			qop = "auth-int"
		} else {
			return nil, errors.New("unknown quality of protection: " + tmp)
		}
	}

	// realm
	var realm []byte
	i = strings.Index(str, "realm=\"")
	if i != -1 {
		realm = message[i+7 : bytes.IndexByte(message[i+7:], '"')+i+7]
	}

	var digesturi string
	// if the server does not provide a realm, use provided ip address or hostname instead
	if realm != nil {
		digesturi = service + "/" + string(realm)
	} else {
		digesturi = service + "/" + host
	}

	cnonce := []byte("123456") // client nonce
	nc := []byte("00000001")   // nonce count

	// build payload
	buf := new(bytes.Buffer)
	buf.WriteString("username=\"")
	buf.WriteString(user)
	if realm != nil {
		buf.WriteString("\",realm=\"")
		buf.Write(realm)
	}
	buf.WriteString("\",nonce=\"")
	buf.Write(snonce)
	buf.WriteString("\",cnonce=\"")
	buf.Write(cnonce)
	buf.WriteString("\",nc=")
	buf.Write(nc)
	if qop != "" {
		buf.WriteString(",qop=")
		buf.WriteString(qop)
	}
	buf.WriteString(",response=\"")

	a1 := calcA1(user, pass, realm, snonce, cnonce)
	buf.Write(calcResp(qop, user, pass, digesturi, a1, realm, snonce, nc, cnonce))

	buf.WriteString("\",digest-uri=\"")
	buf.WriteString(digesturi)
	buf.WriteByte('"')
	if bytes.Contains(message, []byte("charset=utf-8")) {
		buf.WriteString(",charset=utf-8")
	}

	if qop == "auth-int" {
		buf.Write(calcInt(buf.Bytes(), a1))
	}

	return buf.Bytes(), nil
}

// response-value = HEX( KD ( HEX(H(A1)), { nonce-value, ":" nc-value, ":",
// cnonce-value, ":", qop-value, ":", HEX(H(A2)) }))
func calcResp(qop, user, pass, digesturi string, a1, realm, snonce, nc, cnonce []byte) []byte {
	buf := new(bytes.Buffer)
	buf.Write(calcHash(a1))
	buf.WriteByte(':')
	buf.Write(snonce)
	buf.WriteByte(':')
	buf.Write(nc)
	buf.WriteByte(':')
	buf.Write(cnonce)
	buf.WriteByte(':')
	buf.WriteString(qop)
	buf.WriteByte(':')
	if qop == "auth" {
		buf.Write(calcHash([]byte("AUTHENTICATE:" + digesturi)))
	} else {
		buf.Write(calcHash([]byte("AUTHENTICATE:" + digesturi + ":00000000000000000000000000000000")))
	}
	return calcHash(buf.Bytes())
}

// A1 = { H( { username-value, ":", realm-value, ":", passwd } ),
// ":", nonce-value, ":", cnonce-value, ":", authzid-value }
func calcA1(user, pass string, realm, snonce, cnonce []byte) []byte {

	hash := md5.New()
	hash.Write([]byte(user))
	hash.Write([]byte{':'})
	hash.Write(realm)
	hash.Write([]byte{':'})
	hash.Write([]byte(pass))

	a1 := new(bytes.Buffer)
	a1.Write(hash.Sum(nil))
	a1.WriteByte(':')
	a1.Write(snonce)
	a1.WriteByte(':')
	a1.Write(cnonce)

	return a1.Bytes()
}

// hex(md5(x))
func calcHash(in []byte) []byte {
	tmp := md5.Sum(in)
	out := make([]byte, 2*len(tmp))
	hex.Encode(out, tmp[:])
	return out
}

// integrity protection
func calcInt(message []byte, a1 []byte) []byte {
	tmp := md5.Sum(a1)
	key := append(tmp[:], []byte("Digest session key to client-to-server signing key magic constant")...)
	hash := hmac.New(md5.New, key)
	hash.Write([]byte{0, 0, 0, 0}) // sequence number
	hash.Write(message)
	return append(hash.Sum(nil)[:10], 0, 1, 0, 0, 0, 0)
}

// base64 encoding
func base64Encode(in []byte) []byte {
	out := make([]byte, b64.EncodedLen(len(in)))
	b64.Encode(out, []byte(in))
	return out
}

// base64 decoding
func base64Decode(in []byte) []byte {
	in = in[2:]
	out := make([]byte, base64.StdEncoding.DecodedLen(len(in)))
	n, err := base64.StdEncoding.Decode(out, in)
	if err != nil {
		return nil
	}
	return out[:n]
}
