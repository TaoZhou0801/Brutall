// smtp.go implements the brute-force attack against the Simple Mail Transfer Protocol.
//
// Reference:
//		RFC 3207 - SMTP STARTTLS
//		RFC 4954 - SMTP AUTH
//      RFC 5321 - SMTP standard

package main

import (
	"bytes"
	"crypto/md5"
	"errors"
	"strings"
)

type smtpConn struct {
	*conn      // underlying connection
	first bool // first time connection

	*list        // credential list
	user  string // current testing username
	pass  string // current testing password

	resp []byte // server response, valid until next read
	grt  string // user-specified EHLO greeting

	etls   byte                                  // explicit tls
	auth   string                                // authentication method
	method func(int) ([]byte, bool, bool, error) // smtpConn method for authentication
}

func NewSMTP(network, ip, port string, timeout int, list *list, tls bool) *smtpConn {
	// default network tcp
	if network == "" {
		network = "tcp"
	}

	// default port 25 (or 587), 465
	if port == "" {
		if tls {
			port = "465"
		} else {
			port = "25"
		}
	}

	return &smtpConn{
		conn:  newConn(network, ip, port, timeout, tls),
		list:  list,
		first: true,
	}
}

// load module specific options
func (c *smtpConn) SetOption(options map[string]string) bool {
	if len(options) == 0 {
		return true
	}

	if dom, ok := options["dom"]; ok {
		c.setDomain(dom)
		delete(options, "dom")
	}

	if grt, ok := options["grt"]; ok {
		c.grt = grt
		delete(options, "grt")
	}

	if etls, ok := options["etls"]; ok {
		switch etls {
		case "?":
		case "d", "m":
			c.etls = etls[0]
		default:
			c.error("invalid SMTP option [etls]\n")
			c.Option()
			return false
		}
		delete(options, "etls")
	}

	if auth, ok := options["auth"]; ok {
		switch auth {
		case "?":
		case "cm5":
			c.auth = "CRAM-MD5"
			c.method = c.cramAuth
		case "dm5":
			c.auth = "DIGEST-MD5"
			c.method = c.digestAuth
		case "n":
			c.auth = "NTLM"
			c.method = c.ntlmAuth
		case "p":
			c.auth = "PLAIN"
			c.method = c.plainAuth
		case "l":
			c.auth = "LOGIN"
			c.method = c.loginAuth
		default:
			c.error("invalid SMTP option [auth]\n")
			c.Option()
			return false
		}
		delete(options, "uam")
	}

	if len(options) > 0 {
		c.error("unknown SMTP options\n")
		c.Option()
		return false
	}

	return true
}

// print module specific options
func (c *smtpConn) Option() {
	c.info("The following SMTP options are supported:")
	c.info("[dom] append a domain to usernames")
	c.info("      e.g. gmail.com -- user@gmail.com")
	c.info("[grt] choose an EHLO message (domain/ip address)")
	c.info("      e.g. endermite@gmail.com -- \"EHLO endermite@gmail.com\" (default)")
	c.info("[etls] select an SMTP security mechanism")
	c.info("       ? -- let the program decide (default)")
	c.info("       d -- disable explicit tls (STARTTLS)")
	c.info("       m -- mandate explicit tls (STARTTLS)")
	c.info("[auth] select an SMTP authentication method")
	c.info("       ? -- let the program decide (default)")
	c.info("       cm5 -- SASL CRAM-MD5")
	c.info("       dm5 -- SASL DIGEST-MD5")
	c.info("       l -- SASL LOGIN")
	c.info("       n -- SASL NTLM")
	c.info("       p -- SASL PLAIN")
}

// the brute-force attack call
func (c *smtpConn) Run() {
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
func (c *smtpConn) login() bool {
	// process server greeting
	if !c.handshake() {
		return false
	}

	// determine uam in case of first-time connection
	if c.first {
		if !c.probe() {
			return false
		}
		c.first = false
	} else if !c.istls() && c.etls == 'm' && !c.setTLS() || !c.ehlo() {
		return false
	}

	// first time login in one connection
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
func (c *smtpConn) handshake() bool {
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

// determine uam
func (c *smtpConn) probe() bool {
	// capability negotiation
	if c.istls() || c.etls != 'm' {
		if !c.ehlo() {
			return false
		}

		// check available uams
		capa := string(c.resp[4:])
		if c.getAuth(capa) {
			c.etls = 'd'
			return true
		} else if c.etls == 'd' || c.istls() {
			if c.auth == "" {
				c.error("unsupported server UAMs.\nserver response:\n%s", capa)
			} else {
				c.error("server does not support %s.\nserver response:\n%s", c.auth, capa)
			}
			return false
		}
	}

	// tls negotiation
	if !c.setTLS() {
		return false
	}

	// capability negotiation after STARTTLS
	if !c.ehlo() {
		return false
	}

	// last chance for an valid uam
	capa := string(c.resp[4:])
	if c.getAuth(capa) {
		c.etls = 'm'
		return true
	} else {
		if c.auth == "" {
			c.error("unsupported server UAMs.\nserver response:\n%s", capa)
		} else {
			c.error("server does not allow %s.\nserver response:\n%s", c.auth, capa)
		}
		return false
	}
}

// process EHLO request
func (c *smtpConn) ehlo() bool {
	buf := "EHLO "
	if c.grt == "" {
		buf += "endermite@gmail.com"
	} else {
		buf += c.grt
	}

	err := c.write([]byte(buf))
	if err != nil {
		c.error("failed to send EHLO request: %s", err)
		return false
	}

	err = c.read()
	if err != nil {
		c.error("failed to read EHLO response: %s", err)
		return false
	} else if string(c.resp[:3]) != "250" {
		c.error("unexpected EHLO response: %s", c.resp)
		return false
	}

	return true
}

// select server allowed uam
func (c *smtpConn) getAuth(capa string) bool {
	// no authentication specified
	if !strings.Contains(capa, "AUTH ") {
		return false
	}

	if c.auth == "" {
		if strings.Contains(capa, "LOGIN") {
			c.auth = "LOGIN"
			c.method = c.loginAuth
		} else if strings.Contains(capa, "PLAIN") {
			c.auth = "PLAIN"
			c.method = c.plainAuth
		} else if strings.Contains(capa, "CRAM-MD5") {
			c.auth = "CRAM-MD5"
			c.method = c.cramAuth
		} else if strings.Contains(capa, "DIGEST-MD5") {
			c.auth = "DIGEST-MD5"
			c.method = c.digestAuth
		} else if strings.Contains(capa, "NTLM") {
			c.auth = "NTLM"
			c.method = c.ntlmAuth
		} else {
			return false
		}
	} else {
		return strings.Contains(capa, c.auth)
	}

	return true
}

// STARTTLS
func (c *smtpConn) setTLS() bool {
	err := c.write([]byte("STARTTLS"))
	if err != nil {
		c.error("failed to send STARTTLS request: %s", err)
		return false
	}

	err = c.read()
	if err != nil {
		c.error("failed to read STARTTLS response: %s", err)
		return false
	} else if string(c.resp[:3]) != "220" {
		c.error("server does not allow explicit tls")
		return false
	}

	c.useTLS()
	return true
}

/************************************************************************
 *                             Authenticate                             *
 ************************************************************************/

// handle authentication
func (c *smtpConn) authenticate(first bool) (bool, bool) {
	// retrieve username and password
	c.user, c.pass = c.next()

	// authentication stage
	stage := 0
	for {
		// req  -- client request payload
		// skip -- skip current username in case of a '-' response
		// done -- authentication process complete
		// err  -- errors occurred while processing auth message
		req, skip, done, err := c.method(stage)
		if err != nil {
			c.error("%s authentication error: %s", c.auth, err)
			return false, false
		}

		// send client request
		err = c.write(req)
		if err != nil {
			// we are tolerant of errors in subsequent messages
			if first {
				c.error("failed to write %s request: %s", c.auth, err)
				return false, false
			}
			return false, true
		}

		// read server response
		err = c.read()
		if err != nil {
			// some servers might terminate the sessions early
			if done {
				c.set(FAILURE)
				return false, c.has()
			}
			// we are tolerant of errors in subsequent messages
			if first {
				c.error("failed to read %s request: %s", c.auth, err)
				return false, false
			}
			return false, true
		}

		code := string(c.resp[:3])

		// handle final server response
		if done {
			switch code {
			case "235":
				c.set(SUCCESS)
				return false, c.has()
			case "535":
				c.set(FAILURE)
				return c.has(), false
			default:
				c.error("unexpected %s response: %s", c.auth, c.resp)
				return false, false
			}
		}

		// 334 for intermediate auth response
		if code != "334" {
			if skip && code == "535" {
				c.set(SKIP)
				return c.has(), false
			} else {
				c.error("unexpected %s response: %s", c.auth, c.resp)
				return false, false
			}
		}
		stage++
	}
}

// SASL LOGIN authentication
func (c *smtpConn) loginAuth(stage int) ([]byte, bool, bool, error) {
	switch stage {
	case 0:
		// AUTH <SP> LOGIN \r\n
		return []byte("AUTH LOGIN"), false, false, nil

	case 1:
		// base64(user) \r\n
		return base64Encode([]byte(c.user)), true, false, nil

	default:
		// base64(pass) \r\n
		return base64Encode([]byte(c.pass)), false, true, nil
	}
}

// SASL PLAIN authentication
func (c *smtpConn) plainAuth(stage int) ([]byte, bool, bool, error) {
	// AUTH <SP> PLAIN \r\n
	if stage == 0 {
		return []byte("AUTH PLAIN"), false, false, nil
	}

	// base64(sasl_plain) \r\n
	return base64Encode(SaslPlain("", c.user, c.pass)), false, true, nil
}

// SASL CRAM-MD5 authentication
func (c *smtpConn) cramAuth(stage int) ([]byte, bool, bool, error) {
	// AUTH CRAM-MD5 \r\n
	if stage == 0 {
		return []byte("AUTH " + c.auth), false, false, nil
	}

	// decode server challenge
	chal := base64Decode(c.resp)
	if chal == nil {
		return nil, false, false, errors.New("malformed challenge")
	}

	// base64(sasl_scram) \r\n
	return base64Encode(SaslCram(chal, md5.New, c.user, c.pass)), false, true, nil
}

// SASL DIGEST-MD5 authentication
func (c *smtpConn) digestAuth(stage int) ([]byte, bool, bool, error) {
	// AUTH <SP> DIGEST-MD5 \r\n
	if stage == 0 {
		return []byte("AUTH DIGEST-MD5"), false, false, nil
	}

	// decode server challenge
	chal := base64Decode(c.resp)
	if chal == nil {
		return nil, false, false, errors.New("malformed challenge")
	}
	// base64(sasl_digest) \r\n
	out, err := SaslDigest(chal, "smtp", c.ip, c.user, c.pass)
	return base64Encode(out), false, true, err
}

// SASL NTLM authentication
func (c *smtpConn) ntlmAuth(stage int) ([]byte, bool, bool, error) {
	switch stage {
	case 0:
		// AUTH <SP> NTLM \r\ns
		return []byte("AUTH " + c.auth), false, false, nil

	case 1:
		// base64(ntlm_message1) \r\n
		return base64Encode(NtlmNegotiate("", "")), false, false, nil

	default:
		// decode server challenge
		chal := base64Decode(c.resp)
		if chal == nil {
			return nil, false, false, errors.New("malformed challenge")
		}
		// base64(ntlm_message2) \r\n
		return base64Encode(NtlmAuthenticate(chal, "", "", c.user, c.pass)), false, true, nil
	}
}

/************************************************************************
 *                             Read & Write                             *
 ************************************************************************/

// read smtp response, either one-line or multi-line, terminated by "CRLF"
func (c *smtpConn) read() error {
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
	if n < 6 || buf[0] < '2' || buf[0] > '5' || buf[1] < '0' ||
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
func (c *smtpConn) write(data []byte) error {
	err := c.setWriteTimeout()
	if err != nil {
		return err
	}

	return c.conn.write(append(data, '\r', '\n'))
}
