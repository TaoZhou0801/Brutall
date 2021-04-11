/*
conn.go implements the underlying transport layer connection.
*/

package main

import (
	"crypto/tls"
	"net"
	"time"
)

type conn struct {
	// Connection
	tls     bool
	network string
	ip      string
	port    string
	timeout time.Duration
	conn    net.Conn
}

func newConn(network, ip, port string, timeout int, tls bool) (c *conn) {
	c = &conn{network: network, ip: ip, port: port, tls: tls}

	// default timeout 10 seconds
	if timeout == 0 {
		c.timeout = 10 * time.Second
	} else {
		c.timeout = time.Duration(timeout) * time.Second
	}

	return
}

func (c *conn) dial() (err error) {
	if c.tls {
		c.conn, err = tls.DialWithDialer(&net.Dialer{Timeout: c.timeout}, c.network, c.ip+":"+c.port,
			&tls.Config{InsecureSkipVerify: true})
	} else {
		c.conn, err = net.DialTimeout(c.network, c.ip+":"+c.port, c.timeout)
	}
	return
}

func (c *conn) istls() bool {
	return c.tls
}

func (c *conn) useTLS() {
	if !c.tls {
		c.conn = tls.Client(c.conn, &tls.Config{InsecureSkipVerify: true})
		c.tls = true
	}
}

func (c *conn) read(buf []byte) (int, error) {
	return c.conn.Read(buf)
}

func (c *conn) write(buf []byte) error {
	_, err := c.conn.Write(buf)
	return err
}

func (c *conn) setReadTimeout() error {
	return c.conn.SetReadDeadline(time.Now().Add(c.timeout))
}

func (c *conn) setWriteTimeout() error {
	return c.conn.SetWriteDeadline(time.Now().Add(c.timeout))
}

func (c *conn) readTimeout(buf []byte) (int, error) {
	err := c.setReadTimeout()
	if err != nil {
		return 0, err
	}

	return c.read(buf)
}

func (c *conn) writeTimeout(buf []byte) error {
	err := c.setWriteTimeout()
	if err != nil {
		return err
	}

	return c.write(buf)
}

func (c *conn) close() error {
	return c.conn.Close()
}
