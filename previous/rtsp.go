/*
rtsp.go implements brute-force attack against the Real-Time Streaming Protocol (RTSP).

Usage:
	[no option]
	rc := NewRTSP(...)
	rc.Run()

	[with option]
	rc := NewRTSP(...)
	if ok := rc.LoadOpt(...); ok {
		rc.Run()
	}

Note:
	1. In addition to the registered default ports, there is an alternative port 8554 registered.

Reference:
	RTSP Specifics
		https://tools.ietf.org/html/rfc2326
		https://tools.ietf.org/html/rfc7826

	Authentication
		https://tools.ietf.org/html/rfc2617
		https://tools.ietf.org/html/rfc7615
		https://tools.ietf.org/html/rfc7616
		https://tools.ietf.org/html/rfc7617
*/

package main

import (
	"bytes"
	"crypto/md5"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"hash"
)

// var RTSPEndian = binary.BigEndian

type rtspConn struct {
	/* connection */
	*conn /* underlying transport layer connection */

	/* Login */
	*list        /* credential list for brute-force attack */
	mode  Mode   /* authentication mode */
	auth  string /* authentication scheme: basic, digest */

	/* Server */
	path string /* the absolute path, default empty */

	/* Packet */
	header []byte /* store message read */
	body   []byte
}

/* create and initialize a new *rtspConn object */
func NewRTSP(network, ip, port string, timeout int, userlist, passlist []string, tls bool) *rtspConn {
	/* default network tcp */
	if network == "" {
		network = "tcp"
	}

	/* default port 554 (rtsp) & 322 (rtsps) */
	if port == "" {
		if tls {
			port = "322"
		} else {
			port = "554"
		}
	}

	return &rtspConn{conn: NewConn(network, ip, port, timeout, tls), list: NewList(userlist, passlist)}
}

/* load module specific options */
func (rc *rtspConn) LoadOpt(options map[string]string) bool {
	if len(options) == 0 {
		return true
	}

	if path, ok := options["path"]; ok {
		if len(path) > 0 && path[0] != '/' {
			rc.PrintError("invalid option [path]\n")
			rc.ShowOpt()
			return false
		}
		rc.path = path
		delete(options, "path")
	}

	if len(options) > 0 {
		rc.PrintError("invalid module specific options\n")
		rc.ShowOpt()
		return false
	}

	return true
}

/* print module specific options */
func (rc *rtspConn) ShowOpt() {
	rc.PrintInfo("Module RTSP supports the following option:")
	rc.PrintInfo("[path] absolute path")
	rc.PrintInfo("       example: / -- the requested URI will be: rtsp://<ip>:<port>/")
}

/* the one-for-all rtsp brute-force method */
func (rc *rtspConn) Run() {
	recon := true /* reconnection */

	/* try login */
	for recon == true {
		/* initialize transport layer connection */
		err := rc.Dial()
		if err != nil {
			rc.PrintError("failed to connect to the server: %s", err)
			return
		}

		/* continue or not */
		recon = rc.login()

		rc.Close()
	}
}

/************************************************************************
 *                              Try Login                               *
 ************************************************************************/

/* try login */
func (rc *rtspConn) login() bool {
	if rc.auth != "Basic" && !rc.getServerInfo() {
		return false
	}

	firstlogin := true /* first login attempt within the same tcp connection */

	for {
		/* continued login within the same connection */
		if cont, recon := rc.handleAuth(firstlogin); !cont {
			return recon
		}
		firstlogin = false
	}
}

/* acquire the authentication data for first login attempt */
func (rc *rtspConn) getServerInfo() bool {
	/* send an initial message */
	err := rc.write(nil)
	if err != nil {
		rc.PrintError("connection refused")
		return false
	}

	/* check server response */
	errmes, err := rc.read()
	if err != nil {
		rc.PrintError("connection refused")
		return false
	}
	switch errmes[:3] {
	case "200": /* OK */
		rc.PrintResult(NOAUTH)
		return false
	case "401": /* Unauthorized */
	default:
		rc.PrintError("unexpected status code: %s", errmes)
		return false
	}

	/* basic authentication */
	i := bytes.Index(rc.header, []byte("WWW-Authenticate: Basic"))
	if i != -1 {
		if rc.mode == UNKNOWN {
			rc.mode = CRED
		}
		rc.auth = "Basic"
		return true
	}

	/* digest authentication */
	i = bytes.Index(rc.header, []byte("WWW-Authenticate: Digest"))
	if i != -1 {
		if rc.mode == UNKNOWN {
			rc.mode = CRED
		}
		rc.auth = "Digest"
		/* save only the authentication data */
		i += 24
		rc.header = rc.header[i : bytes.IndexByte(rc.header[i:], '\r')+i]
		return true
	}

	/* unknown authentication */
	rc.PrintError("failed to identify authentication prompt:\n%s", rc.header)
	return false
}

/************************************************************************
 *                             Authenticate                             *
 ************************************************************************/

/* do rtsp authentication */
func (rc *rtspConn) handleAuth(firstlogin bool) (bool, bool) {
	var data []byte
	var err error

	/* check authentication scheme */
	if !firstlogin && rc.auth == "Digest" {
		if i := bytes.Index(rc.header, []byte("WWW-Authenticate: Basic")); i != -1 {
			rc.auth = "Basic"
		} else if i = bytes.Index(rc.header, []byte("WWW-Authenticate: Digest")); i != -1 {
			rc.auth = "Digest"
			rc.header = rc.header[i : bytes.IndexByte(rc.header[i:], '\r')+i]
		} else {
			rc.PrintError("failed to identify authentication prompt:\n%s", rc.header)
			return false, false
		}
	}

	/* build authentication payload */
	if rc.auth == "Basic" {
		/* basic authentication */
		data = rc.authBasic(rc.Next(rc.mode))
	} else {
		/* digest authentication */
		data, err = rc.authDigest(rc.Next(rc.mode))
		if err != nil {
			rc.PrintError("invalid digest: %s", err)
			return false, false
		}
	}

	/* send authentication request */
	err = rc.write(data)
	if err != nil {
		/* quit only if we are rejected upon the first login attempt */
		if !firstlogin {
			rc.Retry()
			return false, true
		}
		rc.PrintError("failed to send authentication request: %s", err)
		return false, false
	}

	errmes, err := rc.read()
	if err != nil {
		/* quit only if we are rejected upon the first login attempt */
		if !firstlogin {
			rc.Retry()
			return false, true
		}
		rc.PrintError("failed to read authentication response: %s", err)
		return false, false
	}

	/* check authentication result */
	switch errmes[:3] {
	case "200": /* OK */
		rc.PrintResult(CRED)
		rc.mode = USER
		return false, rc.HasNext(USER)
	case "401": /* Unauthorized */
		rc.mode = CRED
		return rc.HasNext(CRED), false
	default:
		rc.PrintError("unexpected status code: %s", errmes)
		return false, false
	}
}

/* basic authentication: Basic <SP> base64(username + ':' + password) */
func (rc *rtspConn) authBasic(user, pass string) []byte {
	in := make([]byte, len(user)+len(pass)+1)
	i := copy(in, user)
	in[i] = ':'
	copy(in[i+1:], pass)

	enc := base64.StdEncoding
	out := make([]byte, enc.EncodedLen(len(in))+6)
	copy(out, "Basic ")
	base64.StdEncoding.Encode(out[6:], in)

	return out
}

func (rc *rtspConn) authDigest(user, pass string) ([]byte, error) {
	/* realm="testrealm@host.com" */
	i := bytes.Index(rc.header, []byte("realm=\""))
	if i == -1 {
		return nil, errors.New("no realm")
	}
	realm := rc.header[i+7 : bytes.IndexByte(rc.header[i+7:], '"')+i+7]

	/* snonce="dcd98b7102dd2f0e8b11d0f600bfb0c093" */
	i = bytes.Index(rc.header, []byte("nonce=\""))
	if i == -1 {
		return nil, errors.New("no server nonce")
	}
	snonce := rc.header[i+7 : bytes.IndexByte(rc.header[i+7:], '"')+i+7]

	/* opaque="FQhe/qaU925kfnzjCev0ciny7QMkPqMAFRtzCUYo5tdS" */
	var opaque []byte
	i = bytes.Index(rc.header, []byte("opaque=\""))
	if i != -1 {
		opaque = rc.header[i+8 : bytes.IndexByte(rc.header[i+8:], '"')+i+8]
	}

	// A1 := []byte(user + ":" + string(realm) + ":" + pass) /* username ":" unq(realm) ":" passwd */
	// /* "-sess": H(username ":" realm ":" passwd ":" snonce ":" cnonce */
	cnonce := []byte("123456") /* client nonce */
	nc := []byte("00000001")   /* nonce count */

	/* algorithm */
	alg := ""
	i = bytes.Index(rc.header, []byte("algorithm="))
	if i != -1 {
		tmp := rc.header[i+10 : bytes.IndexByte(rc.header[i+10:], ',')+i+10]
		if bytes.HasSuffix(tmp, []byte("MD5")) || bytes.Contains(tmp, []byte("MD5,")) {
			alg = "MD5"
		} else if bytes.HasSuffix(tmp, []byte("SHA-256")) || bytes.Contains(tmp, []byte("SHA-256")) {
			alg = "SHA-256"
		} else if bytes.Contains(tmp, []byte("MD5-sess")) {
			alg = "MD5-sess"
		} else if bytes.Contains(tmp, []byte("SHA-256-sess")) {
			alg = "SHA-256-sess"
		} else {
			return nil, errors.New("unknown algorithm")
		}
	}

	/* quality of protection */
	qop := ""
	i = bytes.Index(rc.header, []byte("qop="))
	if i != -1 {
		tmp := rc.header[i+5 : bytes.IndexByte(rc.header[i+5:], '"')+i+5]
		if bytes.HasSuffix(tmp, []byte("auth")) || bytes.Contains(tmp, []byte("auth,")) {
			qop = "auth"
		} else if bytes.Contains(tmp, []byte("auth-int")) {
			qop = "auth-int"
		} else {
			return nil, errors.New("unknown quality of protection (qop)")
		}
	}

	/* digest-uri */
	uri := "rtsp"
	if rc.tls {
		uri += "s"
	}
	uri += "://" + rc.address + rc.path

	ha1hex := rc.calcA1(alg, user, pass, realm, snonce, cnonce)
	resphex := rc.calcResp(alg, qop, "DESCRIBE", uri, ha1hex, snonce, nc, cnonce)

	/* build Authorization header */
	buf := new(bytes.Buffer)
	buf.WriteString("Digest username=\"")
	buf.WriteString(user)
	buf.WriteString("\", realm=\"")
	buf.Write(realm)
	buf.WriteString("\", uri=\"")
	buf.WriteString(uri)
	if alg != "" {
		buf.WriteString("\", algorithm=")
		buf.WriteString(alg)
	} else {
		buf.WriteByte('"')
	}
	buf.WriteString(", nonce=\"")
	buf.Write(snonce)
	if qop != "" {
		buf.WriteString("\", qop=")
		buf.WriteString(qop)
		buf.WriteString(", nc=")
		buf.Write(nc)
		buf.WriteString(", cnonce=\"")
		buf.Write(cnonce)
	}
	buf.WriteString("\", response=\"")
	buf.Write(resphex)
	if opaque != nil {
		buf.WriteString("\", opaque=\"")
		buf.Write(opaque)
	}
	buf.WriteByte('"')
	return buf.Bytes(), nil
}

/************************************************************************
 *                            Helper Methods                            *
 ************************************************************************/

func (rc *rtspConn) calcA1(alg, user, pass string, realm, snonce, cnonce []byte) []byte {
	var hash hash.Hash
	if alg == "" || alg[:3] == "MD5" {
		hash = md5.New()
	} else {
		hash = sha256.New()
	}
	hash.Write([]byte(user))
	hash.Write([]byte{':'})
	hash.Write(realm)
	hash.Write([]byte{':'})
	hash.Write([]byte(pass))
	ha1 := hash.Sum(nil)

	if len(alg) > 7 && alg[len(alg)-5:] == "-sess" {
		hash.Reset()
		hash.Write(ha1)
		hash.Write([]byte{':'})
		hash.Write(snonce)
		hash.Write([]byte{':'})
		hash.Write(cnonce)
		ha1 = hash.Sum(nil)
	}

	ha1hex := make([]byte, 2*len(ha1))
	hex.Encode(ha1hex, ha1)
	return ha1hex
}

func (rc *rtspConn) calcResp(alg, qop, method, uri string, ha1hex, snonce, nc, cnonce []byte) []byte {
	var hash hash.Hash
	if alg == "" || alg[:3] == "MD5" {
		hash = md5.New()
	} else {
		hash = sha256.New()
	}

	/* calculate H(entity-body) */
	var bodyhex []byte
	if qop == "auth-int" {
		hash.Write(rc.body)
		body := hash.Sum(nil)
		bodyhex = make([]byte, 2*len(body))
		hex.Encode(bodyhex, body)
		hash.Reset()
	}

	/* calculate H(A2) */
	hash.Write([]byte(method))
	hash.Write([]byte{':'})
	hash.Write([]byte(uri))
	if qop == "auth-int" {
		hash.Write([]byte{':'})
		hash.Write(bodyhex)
	}
	ha2 := hash.Sum(nil)
	ha2hex := make([]byte, 2*len(ha2))
	hex.Encode(ha2hex, ha2)

	/* calculate response */
	hash.Reset()
	hash.Write(ha1hex)
	hash.Write([]byte{':'})
	hash.Write(snonce)
	hash.Write([]byte{':'})
	if qop != "" {
		hash.Write(nc)
		hash.Write([]byte{':'})
		hash.Write(cnonce)
		hash.Write([]byte{':'})
		hash.Write([]byte(qop))
		hash.Write([]byte{':'})
	}
	hash.Write(ha2hex)
	resp := hash.Sum(nil)
	resphex := make([]byte, 2*len(resp))
	hex.Encode(resphex, resp)

	return resphex
}

/************************************************************************
 *                            Handle Packets                            *
 ************************************************************************/

/* read message from the server */
func (rc *rtspConn) read() (string, error) {
	buf := make([]byte, 1024)
	n, err := rc.Read(buf)
	if err != nil {
		return "", err
	}

	if string(buf[:5]) != "RTSP/" {
		return "", errors.New("invalid RTSP packet")
	}

	i := bytes.IndexByte(buf[:n], '\r')
	if i < 15 {
		return "", errors.New("invalid RTSP packet")
	}

	j := bytes.Index(buf[i+2:n], []byte("\r\n\r\n"))
	if j == -1 {
		return "", errors.New("invalid RTSP packet")
	}

	rc.header = buf[i+2 : i+j+4]
	rc.body = buf[i+j+6 : n]
	return string(buf[9:i]), nil
}

/* send a DESCRIBE request to the server, with provided Authorization header data */
func (rc *rtspConn) write(data []byte) error {
	length := len(rc.address) + len(rc.path) + 38
	if rc.tls { /* URI: rtsp -> rtsps */
		length++
	}
	if data != nil { /* authorization header */
		length += len(data) + 17
	}
	buf := make([]byte, length)

	/* request: DESCRIBE rtsp://example.com:554[absolute path] RTSP1.0\r\n */
	i := copy(buf, "DESCRIBE ")
	if rc.tls {
		i += copy(buf[i:], "rtsps://")
	} else {
		i += copy(buf[i:], "rtsp://")
	}
	i += copy(buf[i:], rc.address)
	i += copy(buf[i:], rc.path)
	i += copy(buf[i:], " RTSP/1.0\r\n")

	/* headers: Cseq, Authorization */
	i += copy(buf[i:], "CSeq: 0\r\n")
	if data != nil {
		i += copy(buf[i:], "Authorization: ")
		i += copy(buf[i:], data)
		i += copy(buf[i:], "\r\n")
	}
	copy(buf[i:], "\r\n") /* end of headers */

	return rc.Write(buf)
}
