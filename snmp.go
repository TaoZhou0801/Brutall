// snmp.go implements the brute-force attack against the Simple Network Management Protocol.
//
// Note:
// 		The asn1 library gives only DER implementation, while SNMP requires BER.
//     		It is still valid to use asn1.Marshal (but not unmarshal), as DER is a subset of BER.
//      	e.g. DER prohibits leading zeros in long-form length, but BER allows it.
//
// Reference:
//		RFC 1157 - SNMPv1 standard
//      RFC 1213 - MIB-II standard
//      RFC 1901 - SNMPv2c standard
//      RFC 3412 - SNMPv3 standard
//      RFC 3414 - SNMPv3 USM auth

package main

import (
	"encoding/asn1"
	"errors"
	"os"
	"strconv"
	"strings"
	"time"
)

type snmpConn struct {
	*conn      // underlying connection
	first bool // first time connection

	*list // credential list

	resp     []byte                // server response, valid until next read
	ver      int                   // version: 0(1, default), 1(2c), 2(3)
	req      byte                  // request type: get-req (default), get-next-req, set-req
	oid      asn1.ObjectIdentifier // object identifier, 1.3.6.1.2.1.1.1.0 by default
	format   *snmp                 // snmp v1 & v2c packet to be sent
	formatv3 *snmpv3               // snmp v3 packet to be sent

	auth     string // authentication method: HMAC-MD5-96, HMAC-SHA-96, HMAC-SHA-2
	priv     string // encryption: CBC-DES, CFB-AES-128
	trytimes int    // maximum number of trytimes in case of packet loss
}

func NewSNMP(network, ip, port string, timeout int, list *list, tls bool) *snmpConn {
	// default network udp
	if network == "" {
		network = "udp"
	}

	// default port 161
	if port == "" {
		port = "161"
	}

	return &snmpConn{
		conn:  newConn(network, ip, port, timeout, tls),
		list:  list,
		first: true,
	}
}

// load module specific options
func (c *snmpConn) SetOption(options map[string]string) bool {
	if len(options) == 0 {
		return true
	}

	if ver, ok := options["ver"]; ok {
		switch ver {
		case "1":
			c.ver = 0
		case "2":
			c.ver = 1
		case "3":
			c.ver = 3
		default:
			c.error("invalid SNMP option [ver]\n")
			c.Option()
			return false
		}
		delete(options, "ver")
	}

	if req, ok := options["req"]; ok {
		switch req {
		case "g":
			c.req = 0
		case "n":
			c.req = 1
		case "s":
			c.req = 3
		default:
			c.error("invalid SNMP option [req]\n")
			c.Option()
			return false
		}
		delete(options, "req")
	}

	if oidstr, ok := options["oid"]; ok {
		// parse oid
		oids := strings.Split(oidstr, ".")
		oid := make([]int, 0, len(oids))
		for _, item := range oids {
			i, err := strconv.Atoi(item)
			if err != nil {
				c.error("invalid SNMP option [oid]: numbers and dots only\n")
				c.Option()
				return false
			}
			oid = append(oid, i)
		}

		if len(oid) < 2 || oid[0] > 2 || (oid[0] < 2 && oid[1] >= 40) {
			c.error("invalid SNMP option [oid]: invalid oid\n")
			c.Option()
			return false
		}

		c.oid = oid
		delete(options, "oid")
	}

	if len(options) > 0 {
		c.error("unknown SNMP options\n")
		c.Option()
		return false
	}

	return true
}

// print module specific options
func (c *snmpConn) Option() {
	c.info("The following SNMP options are supported:")
	c.info("[ver] select SNMP version")
	c.info("      1 -- version 1 (default)")
	c.info("      2 -- version 2c")
	c.info("      3 -- version 3")
	c.info("[req] select SNMP request type")
	c.info("      g -- get request (default)")
	c.info("      n -- get next request")
	c.info("      s -- set request")
	c.info("	  WARNING: \"set\" will modify variable at given oid, use carefully")
	c.info("[oid] input an SNMP Object Identifier")
	c.info("      e.g. 1.3.6.1.2.1.1.1.0 (default)")
}

// the brute-force attack call
func (c *snmpConn) Run() {
	if c.ver < 2 {
		c.setMode(PASS)
		if c.trytimes == 0 {
			c.trytimes = 1
		}

		// initialize transport layer connection
		err := c.dial()
		if err != nil {
			c.error("dial error: %s", err)
			return
		}
		c.login()
		c.close()

	} else {
		c.setMode(SING)
		if c.trytimes == 0 {
			c.trytimes = 3
		}

		recon := true
		for recon == true {
			// initialize transport layer connection
			err := c.dial()
			if err != nil {
				c.error("dial error: %s", err)
				return
			}
			// continue or not
			recon = c.loginv3()
			c.close()
		}
	}
}

// try login in one connection (v1 & v2c)
func (c *snmpConn) login() bool {
	if !c.authenticate() {
		// failed to send the first request, quit immediately
		return false
	}

	quit := make(chan time.Time)
	done := make(chan bool)

	// response handler
	go c.handle(quit, done)

	// continue until end of list or an error occurred

	for {
		select {
		case <-done:
			return false
		default:
			if !c.authenticate() {
				// send the time when program should terminate
				quit <- time.Now().Add(c.timeout)
				<-done
				return false
			}
		}
	}
}

func (c *snmpConn) loginv3() bool {
	// TODO
	for {
		if cont, recon := c.authenticatev3(); !cont {
			return recon
		}
	}
}

/************************************************************************
 *                               Handshake                              *
 ************************************************************************/

// read usm data
func (c *snmpConn) handshakev3() bool {
	// TODO
	return false
}

/************************************************************************
 *                             Authenticate                             *
 ************************************************************************/

type snmp struct {
	Version   int
	Community []byte
	PDU       asn1.RawValue
}

type pdu struct {
	RequestID   int
	ErrorStatus int
	ErrorIndex  int
	VarBindList []varbind
}

type varbind struct {
	Name  asn1.ObjectIdentifier
	Value asn1.RawValue
}

// build authentication request (v1 & v2c)
func (c *snmpConn) authenticate() bool {
	// retrieve password
	_, pass := c.next()

	if c.first {
		c.first = false

		// default object identifier
		if c.oid == nil {
			c.oid = []int{1, 3, 6, 1, 2, 1, 1, 1, 0}
		}

		pdu := pdu{1234567890, 0, 0, // request id can be arbitrary
			[]varbind{{c.oid, asn1.RawValue{}}}}
		if c.req == 3 {
			pdu.VarBindList[0].Value.Tag = 4 // octet string
		} else {
			pdu.VarBindList[0].Value.Tag = 5 // null value
		}
		tmp, _ := asn1.Marshal(pdu)
		tmp[0] = 160 ^ c.req // change request type

		c.format = &snmp{c.ver, []byte(pass), asn1.RawValue{FullBytes: tmp}}
	} else {
		// only password needs to be updated
		c.format.Community = []byte(pass)
	}
	data, _ := asn1.Marshal(*c.format)

	err := c.write(data)
	if err != nil {
		c.error("failed to send request: %s", err)
		return false
	}

	// responses are handled seperately, temporarily set to failure
	c.set(FAILURE)
	return c.has()
}

// process server response (v1 & v2c)
func (c *snmpConn) handle(quit chan time.Time, done chan bool) {
	var err error
	var end bool
	for {
		// set timeout
		select {
		case deadline := <-quit:
			// terminate after the given deadline
			err = c.conn.conn.SetReadDeadline(deadline)
			end = true
		default:
			// if no quit signal received, refresh deadline
			if !end {
				err = c.setReadTimeout()
			}
		}
		if err != nil {
			c.error("failed to read response: %s", err)
			done <- true
			return
		}

		err = c.read()
		if err == nil {
			// handle result
			size := len(c.resp)
			offset, _ := asn1Len(c.resp) // skip header
			_, j := asn1Len(c.resp[offset:])
			offset += j // skip version
			if offset < size {
				i, j := asn1Len(c.resp[offset:])
				pass := string(c.resp[offset+i : offset+j]) // acquire password
				offset += j                                 // skip password
				if offset < size {
					i, _ = asn1Len(c.resp[offset:])
					offset += i // skip response header
					if offset < size {
						_, j := asn1Len(c.resp[offset:])
						offset += j // skip request id
						if offset+2 < size && c.resp[offset] == 2 &&
							c.resp[offset+1] == 1 && c.resp[offset+2] == 0 {
							// no reported error, login success
							c.setSNMP(pass)
						}
					}
				}
			}
			continue
		} else if errors.Is(err, os.ErrDeadlineExceeded) {
			if !end {
				continue
			}
		} else {
			// handle unknown error
			c.error("failed to read response: %s", err)
		}
		done <- true
		return
	}
}

type snmpv3 struct {
	Version            int
	GlobalData         globalData
	SecurityParameters []byte
	Data               scopedPdu
}

type globalData struct {
	ID            int
	MaxSize       int
	Flags         []byte
	SecurityModel int
}

type usm struct {
	EngineID    []byte
	EngineBoots int
	EngineTime  int
	UserName    []byte
	AuthParam   []byte
	PrivParam   []byte
}

type scopedPdu struct {
	ContextEngineID []byte
	ContextName     []byte
	Data            asn1.RawValue
}

// handle authentication (v3)
func (c *snmpConn) authenticatev3() (bool, bool) {
	// TODO
	return false, false
}

/************************************************************************
 *                             Helper Funcs                             *
 ************************************************************************/

// parse asn1 length
func asn1Len(data []byte) (int, int) {
	// short form
	if data[1] < 128 {
		return 2, int(data[1]) + 2
	}

	// long form
	var size int
	limit := int(data[1]-128) + 2
	for i := 2; i < limit; i++ {
		size *= 256
		size += int(data[i])
	}
	return limit, size + limit
}

/************************************************************************
 *                             Read & Write                             *
 ************************************************************************/

// read snmp response, timeout is handled outside
func (c *snmpConn) read() error {
	// since the go implementation requires us to read udp packet
	// all at once, a larger buffer size is used
	buf := make([]byte, 512)
	n, err := c.conn.read(buf)
	if err != nil {
		return err
	}

	// asn1 constructed sequence
	if buf[0] != 48 {
		return errors.New("malformed packet")
	}

	// read full packet
	c.resp = append([]byte(nil), buf[:n]...)
	_, size := asn1Len(c.resp)
	for len(c.resp) < size {
		n, err = c.conn.read(buf)
		if err != nil {
			return errors.New("malformed packet")
		}
		c.resp = append(c.resp, buf[:n]...)
	}
	return nil
}

// write snmp request
func (c *snmpConn) write(data []byte) error {
	err := c.setWriteTimeout()
	if err != nil {
		return err
	}

	return c.conn.write(data)
}
