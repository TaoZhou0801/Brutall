// imap.go implements the brute-force attack against the Internet Message Access Protocol version 4 revision 1.
//
// Note:
//		"Initial-response argument" described in RFC 4422 is disallowed.
//
// Reference:
//		RFC 2595  - IMAP STARTTLS, LOGINDISABLED
//		RFC 3501  - IMAP(4rev1) standard

package main

import (
	"bytes"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"errors"
	"hash"
	"strings"
)

var (
	imapOK  = []byte{'O', 'K'}
	imapNO  = []byte{'N', 'O'}
	imapBAD = []byte{'B', 'A', 'D'}
	imapBYE = []byte{'B', 'Y', 'E'}
)

type imapConn struct {
	*conn      // underlying connection
	first bool // first time connection

	*list        // credential list
	user  string // current testing username
	pass  string // current testing password

	resp []byte  // server response, valid until next read
	tag  [4]byte // imap command identifier

	etls   byte                                  // explicit tls
	auth   string                                // authentication method
	sc     *SCRAM                                // SASL SCRAM authentication only
	method func(int) ([]byte, bool, bool, error) // imapConn method for authentication
}

func NewIMAP(network, ip, port string, timeout int, list *list, tls bool) *imapConn {
	// default network tcp
	if network == "" {
		network = "tcp"
	}

	// default port 143, 993
	if port == "" {
		if tls {
			port = "993"
		} else {
			port = "143"
		}
	}

	return &imapConn{
		conn:  newConn(network, ip, port, timeout, tls),
		list:  list,
		first: true,
	}
}

// load module specific options
func (c *imapConn) SetOption(options map[string]string) bool {
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
			c.error("invalid IMAP option [etls]\n")
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
		case "cs1":
			c.auth = "CRAM-SHA1"
			c.method = c.cramAuth
		case "cs2":
			c.auth = "CRAM-SHA256"
			c.method = c.cramAuth
		case "dm5":
			c.auth = "DIGEST-MD5"
			c.method = c.digestAuth
		case "n":
			c.auth = "NTLM"
			c.method = c.ntlmAuth
		case "nsl":
			c.auth = "DEFAULT"
			c.method = c.defaultAuth
		case "p":
			c.auth = "PLAIN"
			c.method = c.plainAuth
		case "l":
			c.auth = "LOGIN"
			c.method = c.loginAuth
		case "ss1":
			c.auth = "SCRAM-SHA-1"
			c.method = c.scramAuth
		case "ss2":
			c.auth = "SCRAM-SHA-256"
			c.method = c.scramAuth
		default:
			c.error("invalid IMAP option [auth]\n")
			c.Option()
			return false
		}
		delete(options, "auth")
	}

	if len(options) > 0 {
		c.error("unknown IMAP options\n")
		c.Option()
		return false
	}

	return true
}

// print module specific options
func (c *imapConn) Option() {
	c.info("The following IMAP options are supported:")
	c.info("[dom] append a domain to usernames")
	c.info("      e.g. gmail.com -- users@gmail.com")
	c.info("[etls] select an IMAP security mechanism")
	c.info("       ? -- let the program decide (default)")
	c.info("       d -- disable explicit tls (STARTTLS)")
	c.info("       m -- mandate explicit tls (STARTTLS)")
	c.info("[auth] select an IMAP authentication method")
	c.info("       ? -- let the program decide (default)")
	c.info("       cm5 -- SASL CRAM-MD5")
	c.info("       cs1 -- SASL CRAM-SHA1")
	c.info("       cs2 -- SASL CRAM-SHA256")
	c.info("       dm5 -- SASL DIGEST-MD5")
	c.info("       n -- SASL NTLM")
	c.info("       nsl -- LOGIN (NON-SASL)")
	c.info("       p -- SASL PLAIN")
	c.info("       l -- SASL LOGIN")
	c.info("       ss1 -- SASL SCRAM-SHA-1")
	c.info("       ss2 -- SASL SCRAM-SHA-256")
}

// the brute-force attack call
func (c *imapConn) Run() {
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
func (c *imapConn) login() bool {
	// process server greeting
	if !c.handshake() {
		return false
	}

	// determine uam in case of first-time connection
	if c.first {
		c.first = false
		if !c.probe() {
			return false
		}
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

// read server greeting
func (c *imapConn) handshake() bool {
	// reset tag
	for i := range c.tag {
		c.tag[i] = '0'
	}

	err := c.read()
	if err != nil {
		c.error("failed to read server greeting: %s", err)
		return false
	}

	if len(c.resp) >= 4 && bytes.Equal(c.resp[2:4], imapOK) {
		return true
	} else if len(c.resp) >= 5 && bytes.Equal(c.resp[2:5], imapBYE) {
		c.error("server unavailable")
	} else {
		c.error("unexpected server greeting: %s", c.resp)
	}
	return false
}

// determine uam
func (c *imapConn) probe() bool {
	var err error

	// capability negotiation
	if c.istls() || c.etls != 'm' {
		err = c.write([]byte("CAPABILITY"))
		if err != nil {
			c.error("failed to send CAPABILITY request: %s", err)
			return false
		}

		err = c.read()
		if err != nil {
			c.error("failed to read CAPABILITY response: %s", err)
			return false
		}

		signal := []byte{c.tag[0], c.tag[1], c.tag[2], c.tag[3],
			' ', imapOK[0], imapOK[1]}
		i := bytes.Index(c.resp, signal)
		if i == -1 {
			c.error("unexpected CAPABILITY response: %s", c.resp)
			return false
		}

		capa := string(c.resp[12 : i-2])

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
	err = c.write([]byte("CAPABILITY"))
	if err != nil {
		c.error("failed to send CAPABILITY request: %s", err)
		return false
	}

	err = c.read()
	if err != nil {
		c.error("failed to read CAPABILITY response: %s", err)
		return false
	}

	signal := []byte{c.tag[0], c.tag[1], c.tag[2], c.tag[3],
		' ', imapOK[0], imapOK[1]}
	i := bytes.Index(c.resp, signal)
	if i == -1 {
		c.error("unexpected CAPABILITY response: %s", c.resp)
		return false
	}

	capa := string(c.resp[12 : i-2])

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
func (c *imapConn) getAuth(capa string) bool {
	if c.auth == "" {
		if !strings.Contains(capa, "LOGINDISABLED") {
			c.auth = "DEFAULT"
			c.method = c.defaultAuth
		} else if strings.Contains(capa, "AUTH=LOGIN") {
			c.auth = "LOGIN"
			c.method = c.loginAuth
		} else if strings.Contains(capa, "AUTH=PLAIN") {
			c.auth = "PLAIN"
			c.method = c.plainAuth
		} else if strings.Contains(capa, "AUTH=CRAM-MD5") {
			c.auth = "CRAM-MD5"
			c.method = c.cramAuth
		} else if strings.Contains(capa, "AUTH=CRAM-SHA1") {
			c.auth = "CRAM-SHA1"
			c.method = c.cramAuth
		} else if strings.Contains(capa, "AUTH=CRAM-SHA256") {
			c.auth = "CRAM-SHA256"
			c.method = c.cramAuth
		} else if strings.Contains(capa, "AUTH=DIGEST-MD5") {
			c.auth = "DIGEST-MD5"
			c.method = c.digestAuth
		} else if strings.Contains(capa, "AUTH=SCRAM-SHA-1") {
			c.auth = "SCRAM-SHA-1"
			c.method = c.scramAuth
		} else if strings.Contains(capa, "AUTH=SCRAM-SHA-256") {
			c.auth = "SCRAM-SHA-256"
			c.method = c.scramAuth
		} else if strings.Contains(capa, "AUTH=NTLM") {
			c.auth = "NTLM"
			c.method = c.ntlmAuth
		} else {
			return false
		}
	} else {
		if c.auth == "DEFAULT" {
			return !strings.Contains(capa, "LOGINDISABLED")
		} else {
			return strings.Contains(capa, "AUTH="+c.auth)
		}
	}

	return true
}

// STARTTLS
func (c *imapConn) setTLS() bool {
	err := c.write([]byte("STARTTLS"))
	if err != nil {
		c.error("failed to send STARTTLS request: %s", err)
		return false
	}

	err = c.read()
	if err != nil {
		c.error("failed to read STARTTLS response: %s", err)
		return false
	}

	signal := make([]byte, 5, 8)
	copy(signal, c.tag[:])
	signal[4] = ' '

	if bytes.Contains(c.resp, append(signal, imapOK...)) {
		c.useTLS()
		return true
	} else if bytes.Contains(c.resp, append(signal, imapNO...)) ||
		bytes.Contains(c.resp, append(signal, imapBAD...)) {
		c.error("server does not support explicit tls")
	} else {
		c.error("unexpected STARTTLS response: %s", c.resp)
	}
	return false
}

/************************************************************************
 *                             Authenticate                             *
 ************************************************************************/

// handle authentication
func (c *imapConn) authenticate(first bool) (bool, bool) {
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
		if stage == 0 {
			// mesasge with tag
			err = c.write(req)
		} else {
			// message without tag
			err = c.writeAuth(req)
		}
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
		signal := make([]byte, 5, 8)
		copy(signal, c.tag[:])
		signal[4] = ' '

		if done {
			if c.resp[0] == '+' || bytes.Contains(c.resp, append(signal, imapOK...)) {
				c.set(SUCCESS)
				return false, c.has()
			} else if bytes.Contains(c.resp, append(signal, imapNO...)) ||
				bytes.Contains(c.resp, append(signal, imapBAD...)) {
				c.set(FAILURE)
				return c.has(), false
			} else {
				c.error("unexpected %s response: %s", c.auth, c.resp)
				return false, false
			}
		}

		if c.resp[0] == '+' {
			stage++
			continue
		} else if skip {
			if bytes.Contains(c.resp, append(signal, imapNO...)) ||
				bytes.Contains(c.resp, append(signal, imapBAD...)) {
				c.set(SKIP)
				return c.has(), false
			}
		}

		c.error("unexpected %s response: %s", c.auth, c.resp)
		return false, false
	}
}

// LOGIN authentication
func (c *imapConn) defaultAuth(stage int) ([]byte, bool, bool, error) {
	// <tag> <SP> LOGIN <SP> <username> <SP> <password> \r\n
	return []byte("LOGIN " + c.user + " " + c.pass), false, true, nil
}

// SASL LOGIN authentication
func (c *imapConn) loginAuth(stage int) ([]byte, bool, bool, error) {
	switch stage {
	case 0:
		// <tag> <SP> AUTHENTICATE <SP> LOGIN \r\n
		return []byte("AUTHENTICATE LOGIN"), false, false, nil

	case 1:
		// base64(user) \r\n
		return base64Encode([]byte(c.user)), true, false, nil

	default:
		// base64(pass) \r\n
		return base64Encode([]byte(c.pass)), false, true, nil
	}
}

// SASL PLAIN authentication
func (c *imapConn) plainAuth(stage int) ([]byte, bool, bool, error) {
	// <tag> <SP> AUTHENTICATE <SP> PLAIN \r\n
	if stage == 0 {
		return []byte("AUTHENTICATE PLAIN"), false, false, nil
	}

	// base64(sasl_plain) \r\n
	return base64Encode(SaslPlain("", c.user, c.pass)), false, true, nil
}

// SASL CRAM-[MD5,SHA1,SHA256] authentication
func (c *imapConn) cramAuth(stage int) ([]byte, bool, bool, error) {
	// <tag> <SP> AUTHENTICATE CRAM-[MD5, SHA1, SHA256] \r\n
	if stage == 0 {
		return []byte("AUTHENTICATE " + c.auth), false, false, nil
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
func (c *imapConn) digestAuth(stage int) ([]byte, bool, bool, error) {
	// <tag> <SP> AUTHENTICATE <SP> DIGEST-MD5 \r\n
	if stage == 0 {
		return []byte("AUTHENTICATE DIGEST-MD5"), false, false, nil
	}

	// decode server challenge
	chal := base64Decode(c.resp)
	if chal == nil {
		return nil, false, false, errors.New("malformed challenge")
	}
	// base64(sasl_digest) \r\n
	out, err := SaslDigest(chal, "imap", c.ip, c.user, c.pass)
	return base64Encode(out), false, true, err
}

// SASL SCRAM-SHA-[1,256] authentication
func (c *imapConn) scramAuth(stage int) ([]byte, bool, bool, error) {
	switch stage {
	case 0:
		// <tag> <SP> AUTHENTICATE <SP> SCRAM-SHA-[1,256] \r\n
		return []byte("AUTHENTICATE " + c.auth), false, false, nil

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
func (c *imapConn) ntlmAuth(stage int) ([]byte, bool, bool, error) {
	switch stage {
	case 0:
		// <tag> <SP> AUTHENTICATE <SP> NTLM \r\ns
		return []byte("AUTHENTICATE " + c.auth), false, false, nil

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

// read imap response, either one-line or multi-line, terminated by "CRLF"
func (c *imapConn) read() error {
	err := c.setReadTimeout()
	if err != nil {
		return err
	}

	buf := make([]byte, 256)
	n, err := c.conn.read(buf)
	if err != nil {
		return err
	}

	// multi-line response (non-handshake)
	if buf[0] == '*' && !bytes.Equal(c.tag[:], []byte{'0', '0', '0', '0'}) {
		// last line signal
		signal := []byte{'\r', '\n', c.tag[0], c.tag[1], c.tag[2], c.tag[3], ' '}
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
				if bytes.Contains(c.resp[len(c.resp)-n-6:], signal) {
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

	// one-line response: handshake, continuation, or tag
	if buf[0] == '*' || buf[0] == '+' || bytes.HasPrefix(buf, c.tag[:]) {
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

	return errors.New("malformed packet")
}

// write "CRLF" terminated request
func (c *imapConn) write(data []byte) error {
	err := c.setWriteTimeout()
	if err != nil {
		return err
	}

	// increase tag by 1
	for i := 3; i >= 0; i-- {
		c.tag[i]++
		if c.tag[i] != ':' {
			break
		}
		c.tag[i] -= 10
	}

	// build payload
	buf := make([]byte, len(data)+5, len(data)+7)
	copy(buf, c.tag[:])
	buf[4] = ' '
	copy(buf[5:], data)
	buf = append(buf, '\r', '\n')

	return c.conn.write(buf)
}

// write "CRLF" terminated authentication data
func (c *imapConn) writeAuth(data []byte) error {
	err := c.setWriteTimeout()
	if err != nil {
		return err
	}

	return c.conn.write(append(data, '\r', '\n'))
}
