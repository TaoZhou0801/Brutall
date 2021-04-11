// pop3.go implements the brute-force attack against the Post Office Protocol version 3.
//
// Note:
//		Although RFC 5034 allows an initial-response argument for the AUTH command,
//			some POP3 servers consider it a protocol error (e.g. outlook).
//
// Reference:
//		RFC 1939  - POP3 standard
//		RFC 2245  - POP3 ANONYMOUS
//		RFC 2595  - POP3 STARTTLS
//		RFC 5034  - POP3 AUTH
//		[MS-POP3] - POP3 AUTH NTLM

package main

import (
	"bytes"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"hash"
	"strings"
)

type pop3Conn struct {
	*conn      // underlying connection
	first bool // first time connection

	*list        // credential list
	user  string // current testing username
	pass  string // current testing password

	resp  []byte // server response, valid until next read
	stamp []byte // message timestamp, APOP exclusive

	etls   byte                                  // explicit tls
	auth   string                                // authentication method
	sc     *SCRAM                                // SASL SCRAM authentication only
	method func(int) ([]byte, bool, bool, error) // pop3Conn method for authentication
}

func NewPOP3(network, ip, port string, timeout int, list *list, tls bool) *pop3Conn {
	// default network tcp
	if network == "" {
		network = "tcp"
	}

	// default port 110, 995
	if port == "" {
		if tls {
			port = "995"
		} else {
			port = "110"
		}
	}

	return &pop3Conn{
		conn:  newConn(network, ip, port, timeout, tls),
		list:  list,
		first: true,
	}
}

// load module specific options
func (c *pop3Conn) SetOption(options map[string]string) bool {
	if len(options) == 0 {
		return true
	}

	if dom, ok := options["dom"]; ok {
		c.setDomain(dom)
		delete(options, "dom")
	}

	if etls, ok := options["etls"]; ok {
		switch etls {
		case "?":
		case "d", "m":
			c.etls = etls[0]
		default:
			c.error("invalid POP3 option [etls]\n")
			c.Option()
			return false
		}
		delete(options, "etls")
	}

	if auth, ok := options["auth"]; ok {
		switch auth {
		case "?":
		case "a":
			c.auth = "APOP"
			c.method = c.apopAuth
		case "cm5":
			c.auth = "CRAM-MD5"
			c.method = c.cramAuth
		case "cs1":
			c.auth = "CRAM-SHA1"
			c.method = c.cramAuth
		case "cs2":
			c.auth = "CRAM-SHA256"
			c.method = c.cramAuth
		case "dm5":
			c.auth = "DIGEST-MD5"
			c.method = c.digestAuth
		case "l":
			c.auth = "LOGIN"
			c.method = c.loginAuth
		case "n":
			c.auth = "NTLM"
			c.method = c.ntlmAuth
		case "p":
			c.auth = "PLAIN"
			c.method = c.plainAuth
		case "ss1":
			c.auth = "SCRAM-SHA-1"
			c.method = c.scramAuth
		case "ss2":
			c.auth = "SCRAM-SHA-256"
			c.method = c.scramAuth
		case "u":
			c.auth = "USER"
			c.method = c.userAuth
		default:
			c.error("invalid POP3 option [auth]\n")
			c.Option()
			return false
		}
		delete(options, "auth")
	}

	if len(options) > 0 {
		c.error("unknown POP3 options\n")
		c.Option()
		return false
	}

	return true
}

// print module specific options
func (c *pop3Conn) Option() {
	c.info("The following POP3 options are supported:")
	c.info("[dom] append a domain to usernames")
	c.info("      e.g. gmail.com -- user@gmail.com")
	c.info("[etls] select a POP3 security mechanism")
	c.info("       ? -- let the program decide (default)")
	c.info("       d -- disable explicit tls (STARTTLS)")
	c.info("       m -- mandate explicit tls (STARTTLS)")
	c.info("[auth] select a POP3 authentication method")
	c.info("       ? -- let the program decide (default)")
	c.info("       a -- APOP")
	c.info("       cm5 -- SASL CRAM-MD5")
	c.info("       cs1 -- SASL CRAM-SHA1")
	c.info("       cs2 -- SASL CRAM-SHA256")
	c.info("       dm5 -- SASL DIGEST-MD5")
	c.info("       l -- SASL LOGIN")
	c.info("       n -- SASL NTLM")
	c.info("       p -- SASL PLAIN")
	c.info("       ss1 -- SASL SCRAM-SHA-1")
	c.info("       ss2 -- SASL SCRAM-SHA-256")
	c.info("       u -- USER/PASS")
}

// the brute-force attack call
func (c *pop3Conn) Run() {
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
func (c *pop3Conn) login() bool {
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
	} else if !c.istls() && c.etls == 'm' && !c.setTLS() {
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

// read server greeting and timestamp
func (c *pop3Conn) handshake() bool {
	// read server greeting
	err := c.read()
	if err != nil {
		c.error("failed to read server greeting: %s", err)
		return false
	}

	// non '+' message means either the server is unavailable
	// or it is not a pop3 server
	if c.resp[0] == '-' {
		c.error("server unavailable")
		return false
	}

	// acquire timestamp for APOP authentication
	if c.auth == "" || c.auth == "APOP" {
		c.stamp = nil // remove expired timestamp
		if i := bytes.IndexByte(c.resp[4:], '<'); i != -1 {
			if j := bytes.IndexByte(c.resp[i+5:], '>'); j != -1 {
				c.stamp = make([]byte, j+2)
				copy(c.stamp, c.resp[i+4:i+j+6])
			}
		}
	}

	return true
}

// determine uam
func (c *pop3Conn) probe() bool {
	var err error

	// capability negotiation
	if c.istls() || c.etls != 'm' {
		err = c.write([]byte("CAPA"))
		if err != nil {
			c.error("failed to send CAPA request: %s", err)
			return false
		}

		err = c.readLines()
		if err != nil {
			c.error("failed to read CAPA response: %s", err)
			return false
		} else if c.resp[0] == '-' {
			switch c.auth {
			case "":
				c.auth = "USER"
				c.method = c.userAuth
				fallthrough
			case "USER", "APOP":
				c.etls = 'd'
				return true
			default:
				c.error("server does not support CAPA, try USER or APOP authentication")
				return false
			}
		}

		capa := string(c.resp[4:])

		// anonymous access
		if strings.Contains(capa, "ANONYMOUS") {
			c.set(GUEST)
		}

		// check available uams
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
	err = c.write([]byte("CAPA"))
	if err != nil {
		c.error("failed to send CAPA request: %s", err)
		return false
	}

	err = c.readLines()
	if err != nil {
		c.error("failed to read CAPA response: %s", err)
		return false
	} else if c.resp[0] == '-' {
		c.error("unexpected CAPA response: %s", c.resp)
		return false
	}

	capa := string(c.resp[4:])

	// anonymous access
	if c.etls == 'm' && strings.Contains(capa, "ANONYMOUS") {
		c.set(GUEST)
	}

	// last chance for an valid uam
	if c.getAuth(capa) {
		c.etls = 'm'
		return true
	} else {
		if c.auth == "" {
			c.error("unsupported server UAMs.\nserver response:\n%s", capa)
		} else {
			c.error("server does not support %s.\nserver response:\n%s", c.auth, capa)
		}
		return false
	}
}

// select server allowed uam
func (c *pop3Conn) getAuth(capa string) bool {
	if c.auth == "" {
		if strings.Contains(capa, "USER") {
			c.auth = "USER"
			c.method = c.userAuth
		} else if strings.Contains(capa, "LOGIN") {
			c.auth = "LOGIN"
			c.method = c.loginAuth
		} else if strings.Contains(capa, "APOP") {
			c.auth = "APOP"
			c.method = c.apopAuth
		} else if strings.Contains(capa, "PLAIN") {
			c.auth = "PLAIN"
			c.method = c.plainAuth
		} else if strings.Contains(capa, "CRAM-MD5") {
			c.auth = "CRAM-MD5"
			c.method = c.cramAuth
		} else if strings.Contains(capa, "CRAM-SHA1") {
			c.auth = "CRAM-SHA1"
			c.method = c.cramAuth
		} else if strings.Contains(capa, "CRAM-SHA256") {
			c.auth = "CRAM-SHA256"
			c.method = c.cramAuth
		} else if strings.Contains(capa, "DIGEST-MD5") {
			c.auth = "DIGEST-MD5"
			c.method = c.digestAuth
		} else if strings.Contains(capa, "SCRAM-SHA-1") {
			c.auth = "SCRAM-SHA-1"
			c.method = c.scramAuth
		} else if strings.Contains(capa, "SCRAM-SHA-256") {
			c.auth = "SCRAM-SHA-256"
			c.method = c.scramAuth
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
func (c *pop3Conn) setTLS() bool {
	err := c.write([]byte("STLS"))
	if err != nil {
		c.error("failed to send STLS request: %s", err)
		return false
	}

	err = c.read()
	if err != nil {
		c.error("failed to read STLS response: %s", err)
		return false
	} else if c.resp[0] == '-' {
		c.error("server does not support explicit tls")
		return false
	}

	c.useTLS()
	return true
}

/************************************************************************
 *                             Authenticate                             *
 ************************************************************************/

// handle authentication
func (c *pop3Conn) authenticate(first bool) (bool, bool) {
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

		// handle final server response
		if done {
			if c.resp[0] == '+' {
				c.set(SUCCESS)
				return false, c.has()
			} else {
				c.set(FAILURE)
				return c.has(), false
			}
		}

		if c.resp[0] == '-' {
			if skip {
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

// USER/PASS authentication
func (c *pop3Conn) userAuth(stage int) ([]byte, bool, bool, error) {
	// USER <SP> <username> \r\n
	if stage == 0 {
		return []byte("USER " + c.user), true, false, nil
	}

	// PASS <SP> <password> \r\n
	return []byte("PASS " + c.pass), false, true, nil
}

// APOP authentication
func (c *pop3Conn) apopAuth(stage int) ([]byte, bool, bool, error) {
	// timestamp required for digest calculation
	if c.stamp == nil {
		return nil, false, false, errors.New("server timestamp unspecified")
	}

	// digest = md5(timestamp, password)
	digest := md5.Sum(append([]byte(c.stamp), []byte(c.pass)...))

	// APOP <SP> <username> <SP> <digest> \r\n
	req := make([]byte, len(c.user)+hex.EncodedLen(len(digest))+6)
	i := copy(req, "APOP ")
	i += copy(req[i:], c.user)
	req[i] = ' '
	hex.Encode(req[i+1:], digest[:])

	return req, false, true, nil
}

// SASL LOGIN authentication
func (c *pop3Conn) loginAuth(stage int) ([]byte, bool, bool, error) {
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
func (c *pop3Conn) plainAuth(stage int) ([]byte, bool, bool, error) {
	// AUTH <SP> PLAIN \r\n
	if stage == 0 {
		return []byte("AUTH PLAIN"), false, false, nil
	}

	// base64(sasl_plain) \r\n
	return base64Encode(SaslPlain("", c.user, c.pass)), false, true, nil
}

// SASL CRAM-[MD5,SHA1,SHA256] authentication
func (c *pop3Conn) cramAuth(stage int) ([]byte, bool, bool, error) {
	// AUTH CRAM-[MD5, SHA1, SHA256] \r\n
	if stage == 0 {
		return []byte("AUTH " + c.auth), false, false, nil
	}

	// decode server challenge
	chal := base64Decode(c.resp)
	if chal == nil {
		return nil, false, false, errors.New("malformed challenge")
	}

	var h func() hash.Hash
	switch len(c.auth) {
	case 8:
		// SCRAM-MD5
		h = md5.New
	case 9:
		// SCRAM-SHA1
		h = sha1.New
	default:
		//SCRAM-SHA256
		h = sha256.New
	}

	// base64(sasl_scram) \r\n
	return base64Encode(SaslCram(chal, h, c.user, c.pass)), false, true, nil
}

// SASL DIGEST-MD5 authentication
func (c *pop3Conn) digestAuth(stage int) ([]byte, bool, bool, error) {
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
	out, err := SaslDigest(chal, "pop3", c.ip, c.user, c.pass)
	return base64Encode(out), false, true, err
}

// SASL SCRAM-SHA-[1,256] authentication
func (c *pop3Conn) scramAuth(stage int) ([]byte, bool, bool, error) {
	switch stage {
	case 0:
		// AUTH <SP> SCRAM-SHA-[1,256] \r\n
		return []byte("AUTH " + c.auth), false, false, nil

	case 1:
		if len(c.auth) == 11 {
			// SCRAM-SHA-1
			c.sc = NewSCRAM("", c.user, c.pass, sha1.New, nil)
		} else {
			// SCRAM-SHA-256
			c.sc = NewSCRAM("", c.user, c.pass, sha256.New, nil)
		}
		// base64(sasl_scram_message1) \r\n
		return base64Encode(c.sc.ClientFirstMessage()), true, false, nil

	default:
		// reset SCRAM
		defer func() { c.sc = nil }()

		// decode server challenge
		chal := base64Decode(c.resp)
		if chal == nil {
			return nil, false, false, errors.New("malformed challenge")
		}
		// process server response
		err := c.sc.ServerFirstMessage(chal)
		if err != nil {
			return nil, false, false, err
		}
		// base64(sasl_scram_message2) \r\n
		return base64Encode(c.sc.ClientFinalMessage()), false, true, nil
	}
}

// SASL NTLM authentication
func (c *pop3Conn) ntlmAuth(stage int) ([]byte, bool, bool, error) {
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

// read server response until end is reached
func (c *pop3Conn) readUntil(end []byte) error {
	err := c.setReadTimeout()
	if err != nil {
		return err
	}

	buf := make([]byte, 256)
	n, err := c.conn.read(buf)
	if err != nil {
		return err
	}

	// response indicator must be present
	if buf[0] != '+' && buf[0] != '-' {
		return errors.New("malformed packet")
	}

	// terminator found
	if bytes.HasSuffix(buf[:n], end) {
		c.resp = buf[:n-len(end)]
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
		if bytes.HasSuffix(c.resp, end) {
			c.resp = c.resp[:len(c.resp)-len(end)]
			return nil
		}
	}
}

// read one-line response, terminated by "CRLF"
func (c *pop3Conn) read() error {
	return c.readUntil([]byte{'\r', '\n'})
}

// read multi-line response, terminated by "CRLF.CRLF"
func (c *pop3Conn) readLines() error {
	return c.readUntil([]byte{'\r', '\n', '.', '\r', '\n'})
}

// write "CRLF" terminated request
func (c *pop3Conn) write(data []byte) error {
	err := c.setWriteTimeout()
	if err != nil {
		return err
	}

	return c.conn.write(append(data, '\r', '\n'))
}
