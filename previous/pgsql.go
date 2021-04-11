package main

import (
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"
)

type PGSQLConn struct {
	/* Connection */
	network string
	ip      string
	port    string
	timeout time.Duration
	conn    net.Conn

	/* Account */
	username string
	password string
	database string

	/* Packet */
	message []byte
	mestype byte
	length  int

	/* Authentication */
	*SCRAM
}

func InitPGSQL(network, ip string, port string, timeout time.Duration) *PGSQLConn {
	var mc = &PGSQLConn{network: network, ip: ip}

	/* Mysql default port 3306 */
	if port == "" {
		mc.port = "5432"
	} else {
		mc.port = port
	}

	/* default timeout 10 seconds */
	if timeout == 0 {
		mc.timeout = 10 * time.Second
	} else {
		mc.timeout = timeout
	}

	return mc
}

/* */
func (pc *PGSQLConn) Setup(username, password, database string) {
	pc.username = username
	pc.password = password
	if database == "" {
		pc.database = "postgres"
	} else {
		pc.database = database
	}
}

/* the one-for-all brute force method */
func (pc *PGSQLConn) Brute() (LoginStatus, BruteStatus, error) {
	var err error
	pc.conn, err = net.DialTimeout(pc.network, fmt.Sprintf("%s:%s", pc.ip, pc.port), pc.timeout)
	if err != nil {
		return FAILURE, QUIT, err
	}
	defer pc.conn.Close()

	if err = pc.writeStartup(); err != nil {
		return FAILURE, QUIT, err
	}

	return pc.readMessage()
}

/* build and send the startup message */
func (pc *PGSQLConn) writeStartup() error {
	length := 21 + len(pc.username) + len(pc.database)
	buf := make([]byte, length)

	/* major version 3, minor version 0 */
	buf[1] = '\x03'
	index := 4

	/* parameter name: user */
	index += copy(buf[index:], "user") + 1

	/* parameter value: <username> */
	index += copy(buf[index:], pc.username) + 1

	/* parameter name: database */
	index += copy(buf[index:], "database") + 1

	/* parameter value: <database> */
	copy(buf[index:], pc.database)

	return pc.write(buf, 0)
}

/* read and process the general response from the server */
func (pc *PGSQLConn) readMessage() (LoginStatus, BruteStatus, error) {
	if err := pc.read(); err != nil {
		return FAILURE, QUIT, err
	}

	switch pc.mestype {
	case 'E': /* error response */
		return pc.handleError()
	case 'R': /* authentication request */
		return pc.handleAuth()
	default:
		return FAILURE, QUIT, fmt.Errorf("unkonwn message type %c", pc.mestype)
	}
}

/* read and process error from the server */
func (pc *PGSQLConn) handleError() (LoginStatus, BruteStatus, error) {
	errorcode := pc.readErrorCode()
	if errorcode == "" {
		return FAILURE, QUIT, errors.New("failed to read error code from the packet")
	} else if errorcode == "28000" {
		return FAILURE, NEXTUSER, nil
	} else if errorcode == "28P01" {
		return FAILURE, NEXTPASS, nil
	} else {
		return FAILURE, QUIT, fmt.Errorf("unkonwn auth error code %s", errorcode)
	}
}

/* do authentication with respect to the mechanism specified by the server */
func (pc *PGSQLConn) handleAuth() (LoginStatus, BruteStatus, error) {
	if pc.length < 4 {
		return FAILURE, QUIT, errors.New("unknown auth request packet")
	}

	switch pc.message[3] {
	case 0: /* AuthenticationOk */
		return NOPASS, NEXTUSER, nil

	case 3: /* AuthenticationCleartextPassword */
		if err := pc.write(pc.passwordClear(), 'p'); err != nil {
			return FAILURE, QUIT, fmt.Errorf("failed to send cleartext password: %v", err)
		}
		return pc.readMessage()
	case 5: /* AuthenticationMD5Password */
		if err := pc.write(pc.passwordMD5(pc.message[4:pc.length]), 'p'); err != nil {
			return FAILURE, QUIT, fmt.Errorf("failed to send md5 password: %v", err)
		}
		return pc.readMessage()

	case 10: /* AuthenticationSASL */
		/* as of PostgreSQL 13, only SCRAM-SHA-256 is implemented */
		if !strings.Contains(string(pc.message[4:pc.length]), "SCRAM-SHA-256") {
			return FAILURE, NEXTUSER, fmt.Errorf("server does not support SCRAM-SHA-256")
		}
		/* SCRAM authentication */
		pc.SCRAM = NewSCRAM("", pc.username, pc.password, sha256.New)
		/* send client-first-message */
		mes := pc.WriteClientFirstMessage()
		payload := append([]byte("SCRAM-SHA-256\x00"), []byte{0, 0, 0, byte(len(mes))}...)
		payload = append(payload, mes...)
		if err := pc.write(payload, 'p'); err != nil {
			return FAILURE, QUIT, fmt.Errorf("failed to send first SASL: %v", err)
		}
		return pc.readMessage()

	case 11: /* AuthenticationSASLContinue */
		/* make sure we are in the right stage */
		if pc.Stage() != 1 {
			return FAILURE, QUIT, errors.New("AuthenticationSASLContinue unexpected")
		}
		/* read server-first-message */
		if err := pc.ReadServerFirstMessage(pc.message[4:pc.length]); err != nil {
			return FAILURE, QUIT, err
		}
		/* send client-final-message */
		if err := pc.write(pc.WriteClientFinalMessage(), 'p'); err != nil {
			return FAILURE, QUIT, fmt.Errorf("failed to send final SASL: %v", err)
		}
		return pc.readMessage()

	case 12: /* AuthenticationSASLFinal */
		if pc.Stage() != 2 {
			return FAILURE, QUIT, errors.New("AuthenticationSASLFinal unexpected")
		}
		/* read server-final-message */
		mes, err := pc.ReadServerFinalMessage(pc.message[4:pc.length])
		/* error processing */
		if err != nil {
			return FAILURE, QUIT, err
		} else if mes != nil {
			if strings.Contains(string(mes), "unknown-user") {
				return FAILURE, NEXTUSER, nil
			} else {
				return FAILURE, NEXTPASS, nil
			}
		} else {
			return USERPASS, NEXTUSER, nil
		}
	}

	return FAILURE, QUIT, errors.New("unknown authentication method")
}

/***********************************************************************
 *                        Encrypt Password                             *
 ***********************************************************************/

/* <password> + '\x00' */
func (pc *PGSQLConn) passwordClear() []byte {
	return append([]byte(pc.password), 0)
}

/* "md5" + md5( md5( <password> + <username > ) + salt ) + '\x00' */
func (pc *PGSQLConn) passwordMD5(salt []byte) []byte {
	hash := md5.New()
	hash.Write([]byte(pc.password))
	hash.Write([]byte(pc.username))
	temp := hash.Sum(nil)
	res := make([]byte, hex.EncodedLen(len(temp)))
	hex.Encode(res, temp)

	hash.Reset()
	hash.Write(res)
	hash.Write(salt)
	temp = hash.Sum(nil)
	hex.Encode(res, temp)

	return append(append([]byte("md5"), res...), 0)
}

/***********************************************************************
 *                         Utility Methods                             *
 ***********************************************************************/

/* read parses the received PGSQL packet and saves the message and its type. */
func (pc *PGSQLConn) read() error {
	if err := pc.conn.SetReadDeadline(time.Now().Add(pc.timeout)); err != nil {
		return err
	}

	buf := make([]byte, 256)
	n, err := pc.conn.Read(buf)
	if err != nil {
		return err
	}

	/* read 4-byte big-endian length */
	if pc.length = int(uint32(buf[1])<<24|uint32(buf[2])<<16|uint32(buf[3])<<8|uint32(buf[4])) - 4; n < 5 || pc.length > n-5 {
		return errors.New("unknown PGSQL packet")
	}

	pc.mestype = buf[0]
	pc.message = buf[5:]
	return nil
}

/* readString is a helper function to read a null-terminated string from the message.
   It returns the string read and the index after null. */
func (pc *PGSQLConn) readString(index int) (int, string) {
	start := index
	for pc.message[index] != 0 {
		index++
	}

	return index + 1, string(pc.message[start:index])
}

/* readErrorCode parses error code from an error message (type E).
   It returns an empty string if no error code is found. */
func (pc *PGSQLConn) readErrorCode() string {
	index := 0
	for index < pc.length-1 {
		if pc.message[index] == 'C' {
			_, str := pc.readString(index + 1)
			return str
		} else {
			index, _ = pc.readString(index)
		}
	}
	return ""
}

/* write builds and sends the PGSQL packet with given message type and payload.
   Message type is ignored if it is 0 (used in start up message). */
func (pc *PGSQLConn) write(message []byte, mestype byte) error {
	if err := pc.conn.SetWriteDeadline(time.Now().Add(pc.timeout)); err != nil {
		return err
	}

	length := len(message) + 4
	if mestype != 0 {
		length++
	}
	buf := make([]byte, length)

	/* message type */
	index := 0
	if mestype != 0 {
		buf[index] = byte(mestype)
		index++
		length--
	}

	/* messsage length */
	buf[index+3] = byte(length)
	length >>= 8
	buf[index+2] = byte(length)
	length >>= 8
	buf[index+1] = byte(length)
	length >>= 8
	buf[index] = byte(length)

	/* message body */
	copy(buf[index+4:], message)
	_, err := pc.conn.Write(buf)
	return err
}
