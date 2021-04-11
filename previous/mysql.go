package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"time"
)

type MYSQLConn struct {
	/* Connection */
	network string
	ip      string
	port    string
	timeout time.Duration
	conn    net.Conn

	/* Account */
	username string
	password string

	/* Packet */
	message   []byte
	length    int
	sequence  byte           /* Sequence ID, used for packet tracking. */
	capaflag  [4]byte        /* Server capability flag in little endian. */
	plugin    string         /* user-specific default Authentication plugin. */
	authdata  []byte         /* Authentication plugin data. */
	publickey *rsa.PublicKey /* Unique server public key. */
}

func InitMYSQL(network, ip string, port string, timeout time.Duration) (*MYSQLConn, error) {
	var err error
	var mc = &MYSQLConn{network: network, ip: ip, timeout: timeout}

	/* Mysql default port 3306 */
	if port == "" {
		mc.port = "3306"
	} else {
		mc.port = port
	}

	if timeout == 0 {
		mc.timeout = 10 * time.Second
	}

	mc.conn, err = net.DialTimeout(mc.network, fmt.Sprintf("%s:%s", mc.ip, mc.port), mc.timeout)
	if err != nil {
		return nil, err
	}

	err = mc.probe()
	mc.conn.Close()
	return mc, err
}

func (mc *MYSQLConn) Brute() (LoginStatus, BruteStatus, error) {
	var err error
	if mc.conn, err = net.DialTimeout(mc.network, fmt.Sprintf("%s:%s", mc.ip, mc.port), mc.timeout); err != nil {
		return FAILURE, QUIT, err
	}

	if err = mc.readHandshake(); err != nil {
		return FAILURE, QUIT, err
	}

	if err = mc.writeHandshake(); err != nil {
		return FAILURE, QUIT, err
	}

	return mc.handleAuth()
}

/***********************************************************************
 *                        Encrypt Password                             *
 ***********************************************************************/

/* Reference: https://dev.mysql.com/doc/internals/en/authentication-method.html
   https://dev.mysql.com/doc/dev/mysql-server/latest/page_protocol_connection_phase_authentication_methods.html */

type myrnd struct {
	seed1, seed2, max uint32
}

func (mr *myrnd) myRndInit(seed1, seed2 uint32) {
	mr.max = 0x3FFFFFFF
	mr.seed1 = seed1
	mr.seed2 = seed2
}

func (mr *myrnd) myRnd() float64 {
	mr.seed1 = (mr.seed1*3 + mr.seed2) % mr.max
	mr.seed2 = (mr.seed1 + mr.seed2 + 33) % mr.max
	return float64(mr.seed1) / float64(mr.max)
}

func mysqlHashOld(password []byte) [2]uint32 {
	var nr, nr2, add, tmp uint32 = 1345345333, 0x12345671, 7, 0
	var result [2]uint32
	for _, ch := range password {
		if ch == ' ' || ch == '\t' {
			continue
		}
		tmp = uint32(ch)
		nr ^= (((nr & 63) + add) * tmp) + (nr << 8)
		nr2 += (nr2 << 8) ^ nr
		add += tmp
	}
	result[0] = nr & ((1 << 31) - 1)
	result[1] = nr2 & ((1 << 31) - 1)
	return result
}

/* mysql_old_password:
   https://github.com/atcurtis/mariadb/blob/master/mysys/my_rnd.c */
func (mc *MYSQLConn) scrambleOld() []byte {
	if len(mc.password) == 0 {
		return nil
	}

	hp := mysqlHashOld([]byte(mc.password))
	hn := mysqlHashOld(mc.authdata[:8])

	mr := new(myrnd)
	mr.myRndInit((hp[0] ^ hn[0]), (hp[1] ^ hn[1]))

	scramble := make([]byte, 8)
	for i := range scramble {
		scramble[i] = byte(mr.myRnd()*31) + 64
	}
	extra := byte(mr.myRnd() * 31)
	for i := range scramble {
		scramble[i] ^= extra
	}

	/* null terminated */
	return append(scramble, '\x00')
}

/* mysql_native_password:
   SHA1( password ) XOR SHA1( nonce <concat> SHA1( SHA1( password ) ) ) */
func (mc *MYSQLConn) scrambleNative() []byte {
	if len(mc.password) == 0 {
		return nil
	}

	/* LHS of XOR */
	hash := sha1.New()
	hash.Write([]byte(mc.password))
	scramble := hash.Sum(nil)

	/* RHS of XOR */
	hash.Reset()
	hash.Write(scramble)
	temp := hash.Sum(nil)

	hash.Reset()
	hash.Write(mc.authdata[:20])
	hash.Write(temp)
	temp = hash.Sum(nil)

	/* XOR */
	for i := range scramble {
		scramble[i] ^= temp[i]
	}

	return scramble
}

/* mysql_clear_password:
   null terminated password in plain text */
func (mc *MYSQLConn) scrambleClear() []byte {
	return append([]byte(mc.password), '\x00')
}

/* caching_sha2_password, fast authentication:
   SHA256( password ) XOR SHA256( SHA256( SHA256( password ) ) <concat> nonce ) */
func (mc *MYSQLConn) scrambleSHA2() []byte {
	if len(mc.password) == 0 {
		return nil
	}

	/* LHS of XOR */
	hash := sha256.New()
	hash.Write([]byte(mc.password))
	scramble := hash.Sum(nil)

	/* RHS of XOR */
	hash.Reset()
	hash.Write(scramble)
	temp := hash.Sum(nil)

	hash.Reset()
	hash.Write(temp)
	hash.Write(mc.authdata[:20])
	temp = hash.Sum(nil)

	/* XOR */
	for i := range scramble {
		scramble[i] ^= temp[i]
	}

	return scramble
}

/* sha256_password & caching_sha2_password, full authentication:
   https://insidemysql.com/preparing-your-community-connector-for-mysql-8-part-2-sha256/ */
func (mc *MYSQLConn) scrambleRSA() ([]byte, error) {
	scramble := make([]byte, len(mc.password)+1)
	copy(scramble, mc.password)
	for i := range scramble {
		scramble[i] ^= mc.authdata[i%20]
	}
	return rsa.EncryptOAEP(sha1.New(), rand.Reader, mc.publickey, scramble, nil)
}

/***********************************************************************
 *                          Build Payload                              *
 ***********************************************************************/

/* Reference: https://dev.mysql.com/doc/internals/en/connection-phase-packets.html */

/* probe parses the first handshake packet for server information. */
func (mc *MYSQLConn) probe() error {
	if err := mc.read(); err != nil {
		return fmt.Errorf("Failed to read Handshake packet: %v", err)
	}

	index := 0
	/* Read protocol version. */
	protocol := mc.message[0]
	if protocol < 9 || protocol > 10 {
		return fmt.Errorf("Unsupported protocol version: %d", protocol)
	}
	index++

	/* Read server version. */
	index, version := mc.readString(index)

	/* Skip connection id and null-terminated scramble (part 1). */
	index += 4
	index, _ = mc.readString(index)

	/* Protocol V9 ends here. */
	if protocol == 9 && mc.length != index {
		return errors.New("Failed to parse V9 Handshake packet.")
	}

	/* Copy the lower two bytes of capability */
	copy(mc.capaflag[0:2], mc.message[index:index+2])
	index += 2

	/* Pre-4.1 V10 packet may end here. */
	if index == mc.length {
		return nil
	}

	/* Skip character set and status flags; copy the higher two bytes of capability. */
	index += 1 + 2
	copy(mc.capaflag[2:4], mc.message[index:index+2])
	index += 2

	/* Read length of scramble (0 if CLIENT_AUTH_PLUGIN not set). */
	authlen := int(mc.message[index])
	index++

	/* Skip 10 bytes (reserved). */
	index += 10

	/* If CLIENT_SECURE_CONNECTION is set, skip scramble (part2 ), len = max(13, authlen - 8). */
	if mc.capaflag[1]&(1<<7) != 0 {
		if authlen > 21 {
			index += authlen - 8
		} else {
			index += 13
		}
	}

	/* If CLIENT_PLUGIN_AUTH is set, read the default authentication plugin. */
	if mc.capaflag[2]&(1<<3) != 0 {
		index, _ = mc.readString(index)
	}

	/* Protocol V10 ends here. */
	/* Due to Bug#59453 the auth-plugin-name is missing the terminating NUL-char in versions prior to 5.5.10 and 5.6.2. */
	if index != mc.length && index != mc.length+1 {
		return errors.New("failed to parse V10 Handshake packet")
	}

	fmt.Printf("Mysql server uses protocol %d and is in version %s.\n", protocol, version)
	return nil
}

/* readHandshake reads the handshake packet and extract authentication plugin & data. */
func (mc *MYSQLConn) readHandshake() error {
	if err := mc.read(); err != nil {
		return fmt.Errorf("Failed to read Handshake packet: %v", err)
	}

	/* Skip to sramble part 1. */
	index := 1
	index, _ = mc.readString(index)
	index += 4

	/* Read scramble part 1. */
	index, authdata := mc.readString(index)
	mc.authdata = []byte(authdata)

	/* Return if reaching end of packet or CLIENT_SECURE_CONNECTION is not set. */
	if index+3 == mc.length || mc.capaflag[1]&(1<<7) == 0 {
		return nil
	}

	/* Skip to sramble part 2. */
	index += 7
	authlen := int(mc.message[index])
	index += 11

	/* Read scramble part 2. */
	if authlen > 21 {
		mc.authdata = append(mc.authdata, mc.message[index:index+authlen-8]...)
		index += authlen - 8
	} else {
		mc.authdata = append(mc.authdata, mc.message[index:index+13]...)
		index += 13
	}

	/* If CLIENT_PLUGIN_AUTH is set, read the default authentication plugin. */
	if len(mc.plugin) == 0 && mc.capaflag[2]&(1<<3) != 0 {
		_, mc.plugin = mc.readString(index)
	}

	return nil
}

/* readHandshake builds and sends the handshake response packet. */
func (mc *MYSQLConn) writeHandshake() error {
	var index int
	response := make([]byte, 128, 128)

	isResp41 := mc.capaflag[1]&(1<<1) != 0 /* CLIENT_PROTOCOL_41, determines the response packet type */
	isSecure := mc.capaflag[1]&(1<<7) != 0 /* CLIENT_SECURE_CONNECTION, can do mysql_native_password auth */
	isPlugin := mc.capaflag[2]&(1<<3) != 0 /* CLIENT_PLUGIN_AUTH, contains authentication plugin */

	if isResp41 { /* HandshakeResponse41 */
		response[0] = '\x05' /* Capability flag */
		if isSecure {
			response[1] = '\xa2'
		} else {
			response[1] = '\x22'
		}
		if isPlugin {
			response[2] = '\x08'
		} else {
			response[2] = '\x00'
		}
		response[3] = '\x00'
		response[8] = '\x08' /* Charset: latin1_swedish_ci */
		index = 32
		index += copy(response[index:], mc.username) /* Username */
		index++                                      /* null terminated */

		var authresp []byte /* Client-side generated authentication data */
		if isSecure {
			switch mc.plugin {
			case "mysql_native_password", "":
				authresp = mc.scrambleNative()
			case "mysql_clear_password":
				authresp = mc.scrambleClear()
			case "caching_sha2_password":
				authresp = mc.scrambleSHA2()
			case "sha256_password":
				/* Avoid using CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA to send long password hash */
				if len(mc.password) == 0 {
					authresp = nil
				} else {
					authresp = []byte{'\x01'}
				}
			default:
				return errors.New("Unsupported Authentication method")
			}

			response[index] = byte(len(authresp)) /* Authentication data length */
			index++
			index += copy(response[index:], authresp) /* Authentication data */

			if isPlugin {
				index += copy(response[index:], mc.plugin) /* Authentication plugin */
				index++                                    /* null terminated */
			}
		} else {
			index += copy(response[index:], mc.scrambleOld()) /* Authentication data */
		}
	} else { /* HandshakeResponse320 */
		response[0] = '\x05' /* Capability flags */
		response[1] = '\x20'
		response[2] = '\x00' /* Max packet size */
		response[3] = '\x00'
		response[4] = '\x00'
		index = 5
		index += copy(response[index:], mc.username)      /* Username */
		index++                                           /* null terminated */
		index += copy(response[index:], mc.scrambleOld()) /* Authentication data */
	}

	if err := mc.write(response[:index]); err != nil {
		return fmt.Errorf("Failed in sending handshake response: %v", err)
	}
	return nil
}

func (mc *MYSQLConn) handleAuth() (LoginStatus, BruteStatus, error) {
	if err := mc.read(); err != nil {
		return FAILURE, QUIT, fmt.Errorf("failed to read Auth response: %v", err)
	}

	switch mc.message[0] {
	case '\x00': /* Login Success */
		return USERPASS, NEXTUSER, nil

	case '\x01': /* More Data */
		if mc.length == 2 {
			if mc.message[1] == 3 { /* Login Success */
				return USERPASS, NEXTUSER, nil
			} else if mc.message[1] == 4 {
				if mc.publickey == nil { /* Request for public key if not already acquired */
					if err := mc.write([]byte{'\x02'}); err != nil {
						return FAILURE, QUIT, fmt.Errorf("failed to send auth public key request: %v", err)
					}
				} else { /* Encrypt and send RSA */
					payload, err := mc.scrambleRSA()
					if err != nil {
						return FAILURE, QUIT, fmt.Errorf("failed to build RSA response: %v", err)
					}
					if err := mc.write(payload); err != nil {
						return FAILURE, QUIT, fmt.Errorf("failed to send RSA response: %v", err)
					}
				}
				return mc.handleAuth()
			}
		} else if mc.plugin == "caching_sha2_password" || mc.plugin == "sha256_password" {
			/* Save a copy of server public key if not acquired beforehand */
			if mc.publickey == nil {
				if err := mc.readPublickey(); err != nil {
					return FAILURE, QUIT, fmt.Errorf("failed to read server public key: %v", err)
				}
			}
			/* Encrypt and send RSA */
			payload, err := mc.scrambleRSA()
			if err != nil {
				return FAILURE, QUIT, fmt.Errorf("failed to build RSA response: %v", err)
			}
			if err := mc.write(payload); err != nil {
				return FAILURE, QUIT, fmt.Errorf("failed to send RSA response: %v", err)
			}
			return mc.handleAuth()
		}
		return FAILURE, QUIT, errors.New("unkonwn AuthMoreData packet")

	case '\xfe': /* Auth Switch */
		var index int
		if mc.length == 1 { /*Old Auth Switch */
			mc.plugin = "mysql_old_password"
		} else {
			index, mc.plugin = mc.readString(1)
			_, auth := mc.readString(index)
			mc.authdata = []byte(auth)
		}
		var authresp []byte
		switch mc.plugin {
		case "mysql_native_password":
			authresp = mc.scrambleNative()
		case "mysql_old_password":
			authresp = mc.scrambleOld()
		case "mysql_clear_password":
			authresp = mc.scrambleClear()
		case "caching_sha2_password":
			authresp = mc.scrambleSHA2()
		case "sha256_password":
			if len(mc.password) == 0 {
				authresp = nil
			} else {
				authresp = []byte{'\x01'}
			}
		default:
			/* Authentication methods are user-specific. If we are lucky, some accounts may implement plugins we understand. */
			return FAILURE, NEXTUSER, fmt.Errorf("failed in process auth switch, unsupported Auth method: %s", mc.plugin)
		}
		if err := mc.write(authresp); err != nil {
			return FAILURE, QUIT, errors.New("failed in sending auth switch request")
		}
		return mc.handleAuth()

	case '\xff': /* Error */
		if mc.message[1] == '\x15' && mc.message[2] == '\x04' { /* 1045-Access Denied */
			return FAILURE, NEXTPASS, nil
		}
		var errmes string /* Read error message from server. */
		if mc.capaflag[1]&(1<<1) != 0 {
			_, errmes = mc.readString(9)
		} else {
			_, errmes = mc.readString(3)
		}
		return FAILURE, QUIT, errors.New(errmes)
	}
	return FAILURE, QUIT, errors.New("unknown mysql packet")
}

/***********************************************************************
 *                         Utility Methods                             *
 ***********************************************************************/

/* Reference: https://dev.mysql.com/doc/internals/en/mysql-packet.html */

/* Read mysql packet: length <3> + sequence <1> + payload <length>, save the payload. */
func (mc *MYSQLConn) read() error {
	if err := mc.conn.SetReadDeadline(time.Now().Add(mc.timeout)); err != nil {
		return err
	}

	/* Packets in connection phase have size not exceeding 452 bytes (RSA),
	unless server version is awkwardly long. */
	buf := make([]byte, 512)
	n, err := mc.conn.Read(buf)
	if err != nil {
		return err
	}

	mc.length = int(uint32(buf[0]) | uint32(buf[1])<<8 | uint32(buf[2])<<16)
	if mc.length != n-4 {
		return errors.New("Unknown packet.")
	}

	mc.sequence = buf[3]
	mc.message = buf[4:]
	return nil
}

/* readString is a helper function to read a null-terminated string from the message.
   It returns the string read and the index after null. */
func (mc *MYSQLConn) readString(index int) (int, string) {
	start := index
	for mc.message[index] != 0 {
		index++
	}

	return index + 1, string(mc.message[start:index])
}

/* readPublickey is a helper function to read server public key from the message.
   It stores the key in mc.publickey. */
func (mc *MYSQLConn) readPublickey() error {
	if len(mc.message) == 0 {
		return errors.New("message has length 0")
	}

	block, _ := pem.Decode(mc.message[1:])
	if block == nil {
		return errors.New("not a pem-formated block")
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return err
	}

	var ok bool
	mc.publickey, ok = pub.(*rsa.PublicKey)
	if !ok {
		return errors.New("not a RSA publickey")
	}

	return nil
}

/* Write mysql packet: length <3> + sequence <1> + payload <length>. */
func (mc *MYSQLConn) write(message []byte) error {
	if err := mc.conn.SetWriteDeadline(time.Now().Add(mc.timeout)); err != nil {
		return err
	}
	length := len(message)
	payload := make([]byte, 4+len(message))
	payload[0] = byte(length)
	payload[1] = byte(length >> 8)
	payload[2] = byte(length >> 16)
	payload[3] = mc.sequence + 1
	copy(payload[4:], message)
	_, err := mc.conn.Write(payload)
	return err
}
