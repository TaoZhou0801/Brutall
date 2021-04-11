// ftp.go implements the brute-force attack against the File Transfer Protocol.
//
// Reference:
//		RFC 959  - FTP standard
//		RFC 4217 - FTP TLS

package main

import (
	"bytes"
	"errors"
	"strings"
)

type ftpConn struct {
	*conn // underlying connection

	*list // credential list

	resp []byte // server response, valid until next read

	etls byte // explicit tls
}

func NewFTP(network, ip, port string, timeout int, list *list, tls bool) *ftpConn {
	// default network tcp
	if network == "" {
		network = "tcp"
	}

	// default port 21, 990
	if port == "" {
		if tls {
			port = "990"
		} else {
			port = "21"
		}
	}

	return &ftpConn{
		conn: newConn(network, ip, port, timeout, tls),
		list: list,
	}
}

// load module specific options
func (c *ftpConn) SetOption(options map[string]string) bool {
	if len(options) == 0 {
		return true
	}

	if etls, ok := options["etls"]; ok {
		switch etls {
		case "?":
		case "d", "m":
			c.etls = etls[0]
		default:
			c.error("invalid FTP option [etls]\n")
			c.Option()
			return false
		}
		delete(options, "etls")
	}

	if len(options) > 0 {
		c.error("unknown FTP options\n")
		c.Option()
		return false
	}

	return true
}

// print module specific options
func (c *ftpConn) Option() {
	c.info("The following FTP option is supported:")
	c.info("[etls] select a FTP security mechanism")
	c.info("      ? -- let the program decide (default)")
	c.info("      d -- disable explicit tls")
	c.info("      m -- mandate explicit tls")
}

// the brute-force attack call
func (c *ftpConn) Run() {
	c.setMode(SING)

	recon := true
	for recon == true {
		// initialize transport layer connection
		err := c.dial()
		if err != nil {
			c.error("dial error: %s", err)
			return
		}
		// continue or not
		recon = c.login()
		c.close()
	}
}

// try login in one connection
func (c *ftpConn) login() bool {
	if !c.handshake() {
		return false
	}

	first := true
	for {
		if cont, recon := c.authenticate(first); !cont {
			return recon
		}
		first = false
	}
}

/************************************************************************
 *                               Handshake                              *
 ************************************************************************/

// read server greeting
func (c *ftpConn) handshake() bool {
	err := c.read()
	if err != nil {
		c.error("failed to read server greeting: %s", err)
		return false
	}

	if string(c.resp[:3]) != "220" {
		c.error("unexpected server greeting: %s", c.resp)
		return false
	}

	return true
}

/************************************************************************
 *                             Authenticate                             *
 ************************************************************************/

// handle authentication
func (c *ftpConn) authenticate(first bool) (bool, bool) {
	var err error

	// explicit tls
	if first && !c.istls() && c.etls == 'm' {
		err = c.write([]byte("AUTH TLS"))
		if err != nil {
			c.error("failed to send tls request: %s", err)
			return false, false
		}

		err = c.read()
		if err != nil {
			c.error("failed to read tls response: %s", err)
			return false, false
		}

		switch string(c.resp[:3]) {
		case "534":
			c.error("server does not support tls")
			return false, false
		case "234":
		default:
			c.error("unexpected tls response: %s", c.resp)
			return false, false
		}

		c.useTLS()
	}

	// retrieve username and password
	user, pass := c.next()

	// try username
	err = c.write([]byte("USER " + user))
	if err != nil {
		if first {
			c.error("failed to send user request: %s", err)
			return false, false
		} else {
			return false, true
		}
	}

	err = c.read()
	if err != nil {
		if first {
			c.error("failed to read user response: %s", err)
			return false, false
		} else {
			return false, true
		}
	}

	switch string(c.resp[:3]) {
	case "230":
		c.set(NOPASS)
		return false, c.has()
	case "331":
	case "530":
		mes := strings.ToLower(string(c.resp[4:]))
		if strings.Contains(mes, "tls") || strings.Contains(mes, "secure") {
			if c.etls == 'd' {
				c.error("server requires explicit tls")
				return false, false
			} else {
				c.etls = 'm'
				return true, false
			}
		} else {
			c.set(SKIP)
			return c.has(), false
		}
	default:
		c.error("unexpected user response: %s", c.resp)
		return false, false
	}

	// try password
	err = c.write([]byte("PASS " + pass))
	if err != nil {
		c.error("failed to send pass request: %s", err)
		return false, false
	}

	err = c.read()
	if err != nil {
		c.set(FAILURE)
		return false, c.has()
	}

	switch string(c.resp[:3]) {
	case "230":
		c.set(SUCCESS)
		return false, c.has()
	case "530":
		c.set(FAILURE)
		return c.has(), false
	default:
		c.error("unexpected pass response: %s", c.resp)
		return false, false
	}
}

/************************************************************************
 *                             Read & Write                             *
 ************************************************************************/

// read ftp response, either one-line or multi-line, terminated by "CRLF"
func (c *ftpConn) read() error {
	err := c.setReadTimeout()
	if err != nil {
		return err
	}

	buf := make([]byte, 256)
	n, err := c.conn.read(buf)
	if err != nil {
		return err
	}

	// server reply code
	if n < 6 || buf[0] < '1' || buf[0] > '6' || buf[1] < '0' ||
		buf[1] > '5' || buf[2] < '0' || buf[2] > '9' {
		return errors.New("malformed packet")
	}

	// multi-line response
	if buf[3] == '-' {
		// last line signal
		signal := []byte{'\r', '\n', buf[0], buf[1], buf[2], ' '}
		if !bytes.Contains(buf[:n], signal) {
			// more contents to read
			c.resp = append([]byte(nil), buf[:n]...)
			for {
				n, err = c.conn.read(buf)
				if err != nil {
					return errors.New("malformed packet")
				}

				c.resp = append(c.resp, buf[:n]...)

				// search for last line
				if bytes.Contains(c.resp[len(c.resp)-n-5:], signal) {
					for {
						// terminator found
						if bytes.HasSuffix(buf[:n], []byte{'\r', '\n'}) {
							c.resp = c.resp[:len(c.resp)-2]
							return nil
						}

						n, err = c.conn.read(buf)
						if err != nil {
							return errors.New("malformed packet")
						}

						c.resp = append(c.resp, buf[:n]...)
					}
				}
			}
		}
	}

	// terminator found
	if bytes.HasSuffix(buf[:n], []byte{'\r', '\n'}) {
		c.resp = buf[:n-2]
		return nil
	}

	// more contents to read
	c.resp = append([]byte(nil), buf[:n]...)
	for {
		n, err = c.conn.read(buf)
		if err != nil {
			return errors.New("malformed packet")
		}

		c.resp = append(c.resp, buf[:n]...)

		// search for terminator
		if bytes.HasSuffix(c.resp, []byte{'\r', '\n'}) {
			c.resp = c.resp[:len(c.resp)-2]
			return nil
		}
	}
}

// write "CRLF" terminated request
func (c *ftpConn) write(data []byte) error {
	err := c.setWriteTimeout()
	if err != nil {
		return err
	}

	return c.conn.write(append(data, '\r', '\n'))
}
