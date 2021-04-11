// redis.go implements brute-force attack against RESP (Redis Serialization Protocol).
//
// Reference:
// 		https://redis.io/documentation

package main

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
)

// var RedisEndian = binary.BigEndian

type redisConn struct {
	*conn // underlying connection
	first bool

	*list // credential list

	resp []byte // server response, valid until next read

	acl bool // the server is using the ACL System (username required)
}

func NewRedis(network, ip, port string, timeout int, list *list, tls bool) *redisConn {
	// default network tcp
	if network == "" {
		network = "tcp"
	}

	// default port 6379
	if port == "" {
		port = "6379"
	}

	return &redisConn{
		conn:  newConn(network, ip, port, timeout, tls),
		list:  list,
		first: true,
	}
}

// load module specific options
func (c *redisConn) SetOption(options map[string]string) bool {
	if len(options) > 0 {
		c.error("unknown Redis options\n")
		c.Option()
		return false
	}

	return true
}

// print module specific options
func (c *redisConn) Option() {
	c.info("Module Redis supports no options")
}

// the brute-force attack call
func (c *redisConn) Run() {
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

// try login
func (c *redisConn) login() bool {
	if c.first {
		if !c.probe() {
			return false
		}
		c.first = false
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

// check if the Redis server supports ACL commands
func (c *redisConn) probe() bool {
	// a single "ACL" command encoded in Redis format
	err := c.write([]byte("*1\r\n$3\r\nACL\r\n"))
	if err != nil {
		c.error("failed to write ACL request: %s", err)
		return false
	}

	err = c.read()
	if err != nil {
		c.error("failed to read ACL response: %s", err)
		return false
	}

	// check response
	resp := string(c.resp)
	if strings.HasPrefix(resp, "-ERR unknown command") {
		// ACL unavailable, Redis Pre-6.0.0
		c.setMode(PASS)
		return true
	} else if strings.HasPrefix(resp, "-ERR wrong number of arguments") {
		// ACL available, Redis 6.0.0+
		c.acl = true
		c.setMode(MULT)
		return true
	} else if strings.HasPrefix(resp, "-DENIED") {
		c.error("access denied")
		return false
	} else {
		c.error("unexpected ACL response: %s", resp)
		return false
	}
}

/************************************************************************
 *                             Authenticate                             *
 ************************************************************************/

// handle authentication
func (c *redisConn) authenticate(first bool) (bool, bool) {
	// retrieve username and password
	user, pass := c.next()

	// build auth payload
	var err error
	if c.acl {
		// a Redis 6.0 instance, or greater, is using the Redis ACL system
		err = c.write([]byte(fmt.Sprintf("*3\r\n$4\r\nAUTH\r\n$%d\r\n%s\r\n$%d\r\n%s\r\n",
			len(user), user, len(pass), pass)))
	} else {
		// the Redis server is password protected via the requirepass option
		err = c.write([]byte(fmt.Sprintf("*2\r\n$4\r\nAUTH\r\n$%d\r\n%s\r\n",
			len(pass), pass)))
	}
	if err != nil {
		// we are tolerant of errors in subsequent messages
		if first {
			c.error("failed to write non-acl auth request: %s", err)
			return false, false
		}
		return false, true
	}

	// read auth response
	err = c.read()
	if err != nil {
		// we are tolerant of errors in subsequent messages
		if first {
			c.error("failed to read non-acl auth request: %s", err)
			return false, false
		}
		return false, true
	}

	// handle auth result
	resp := string(c.resp)
	if strings.HasPrefix(resp, "-ERR invalid password") ||
		strings.HasPrefix(resp, "-WRONGPASS") {
		c.set(FAILURE)
		return c.has(), false
	} else if strings.HasPrefix(resp, "+OK") {
		c.set(SUCCESS)
		// reconnection not needed
		return c.has(), false
	} else if strings.Contains(resp, "no password is set") {
		c.set(NOAUTH)
		return false, false
	} else {
		c.error("unexpected non-acl auth response: %s", resp)
		return false, false
	}
}

/************************************************************************
 *                             Read & Write                             *
 ************************************************************************/

// read "CRLF" terminated redis response
func (c *redisConn) read() error {
	err := c.setReadTimeout()
	if err != nil {
		return err
	}

	buf := make([]byte, 256)
	n, err := c.conn.read(buf)
	if err != nil {
		return err
	}

	// RESP simple strings and errors only
	if buf[0] != '+' && buf[0] != '-' {
		return errors.New("malformed packet")
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

// write redis request
func (c *redisConn) write(data []byte) error {
	err := c.setWriteTimeout()
	if err != nil {
		return err
	}

	return c.conn.write(data)
}
