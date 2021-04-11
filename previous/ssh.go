// this module is incomplete

package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"math/big"
	"strings"
)

/* an incomplete list of commands */
const (
	SSH_MSG_KEXINIT     byte = 20
	SSH_MSG_NEWKEYS     byte = 21
	SSH_MSG_KEXDH_INIT  byte = 30
	SSH_MSG_KEXDH_REPLY byte = 31
)

const (
	OAKLEY_GROUP_2_PRIME   = "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381FFFFFFFFFFFFFFFF"
	OAKLEY_GROUP_14_PRIME  = "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF"
	OAKLEY_GROUP_GENERATOR = 2
)

var SSHEndian = binary.BigEndian

type sshConn struct {
	/* connection */
	*conn /* underlying transport layer connection */

	/* Packet */
	message []byte /* store message read */
	raw     []byte /* store message read but not yet used */

	/* Server */
	algo map[string][]string /* ssh specific algorithms */

	/* Login */
	*list      /* credential list for brute-force attack */
	mode  Mode /* authentication mode */
}

/* create and initialize a new *sshConn object */
func NewSSH(network, ip, port string, timeout int, userlist, passlist []string, tls bool) *sshConn {
	/* default network tcp */
	if network == "" {
		network = "tcp"
	}

	/* default port 22 */
	if port == "" {
		port = "22"
	}

	return &sshConn{conn: NewConn(network, ip, port, timeout, tls), list: NewList(userlist, passlist),
		algo: map[string][]string{
			"kex": {"diffie-hellman-group14-sha1"}, /* key exchange */ // "diffie-hellman-group1-sha1"
			"pky": {"ssh-rsa"},                     /* public key */   //"ssh-dss"
			"enc": {"3des-cbc", "aes128-ctr"},      /* encryption */
			"mac": {"hmac-sha1"},                   /* data integrity */
			"cpr": {"none"},                        /* compression */
			"lan": {},                              /* language */
		},
	}
}

/* load module specific options */
func (sc *sshConn) LoadOpt(options map[string]string) bool {
	if len(options) > 0 {
		sc.PrintError("invalid module specific options\n")
		sc.ShowOpt()
		return false
	}

	return true
}

/* print module specific options */
func (sc *sshConn) ShowOpt() {
	sc.PrintInfo("Module SSH supports no options")
}

/* the one-for-all ssh brute-force method */
func (sc *sshConn) Run() {
	recon := true /* reconnection */

	/* try login */
	for recon == true {
		/* initialize transport layer connection */
		err := sc.Dial()
		if err != nil {
			sc.PrintError("failed to connect to the server: %s", err)
			return
		}

		/* continue or not */
		recon = sc.login()

		sc.Close()
	}
}

/************************************************************************
 *                              Try Login                               *
 ************************************************************************/

/* try login */
func (sc *sshConn) login() bool {
	if !sc.handshake() {
		return false
	}

	return false
}

func (sc *sshConn) handshake() bool {
	/* send protocol version */
	err := sc.writeVersion([]byte("SSH-2.0-Endermite\r\n"))
	if err != nil {
		sc.PrintError("failed to send SSH protocol version: %s", err)
		return false
	}

	/* send client key exchange init */
	err = sc.write(SSH_MSG_KEXINIT, sc.kexInit())
	if err != nil {
		sc.PrintError("failed to send SSH key exchange init: %s", err)
		return false
	}

	/* read server protocol version */
	for {
		/* server is allowed to send other lines before the version string */
		err = sc.readVersion()
		if err != nil {
			sc.PrintError("failed to read SSH protocol version: %s", err)
			return false
		}
		if len(sc.message) > 7 && string(sc.message[:8]) == "SSH-2.0-" {
			break
		}
	}

	/* read server key exchange init */
	err = sc.read()
	if err != nil {
		sc.PrintError("failed to read SSH key exchange init: %s", err)
		return false
	}
	if sc.message[0] != SSH_MSG_KEXINIT {
		sc.PrintError("failed to read SSH key exchange init: wrong message code")
		return false
	}

	/* select algorithms */
	if !sc.selectAlgo(sc.message[17:]) {
		return false
	}

	return sc.kex()
}

func (sc *sshConn) kex() bool {
	/* send dh client public key */
	if sc.algo["kex"][0] == "diffie-hellman-group1-sha1" {
	}

	p, _ := new(big.Int).SetString(OAKLEY_GROUP_14_PRIME, 16)
	g := big.NewInt(OAKLEY_GROUP_GENERATOR)
	x := big.NewInt(10000)
	e := new(big.Int).Exp(g, x, p)
	buf := make([]byte, 260)
	e.FillBytes(buf) /* 4-byte length + 256-byte client key */
	buf[2] = 1

	err := sc.write(SSH_MSG_KEXDH_INIT, buf)
	if err != nil {
		sc.PrintError("failed to send key exchange (diffie-hellman-group1-sha1): %s", err)
		return false
	}

	/* read server protocol version */
	err = sc.read()
	if err != nil {
		sc.PrintError("failed to read key exchange (diffie-hellman-group1-sha1): %s", err)
		return false
	}
	if sc.message[0] != SSH_MSG_KEXDH_REPLY {
		sc.PrintError("invalid key exchange (diffie-hellman-group1-sha1) message code: %d", sc.message[0])
	}

	return false
}

/************************************************************************
 *                            Helper Methods                            *
 ************************************************************************/

/* blockSize returns the cipher block size or 8, whichever is larger (for paddings) */
func (sc *sshConn) blockSize(alg string) int {
	switch alg {
	case "3des-cbc":
		return 8
	case "aes128-ctr":
		return 16
	default:
		return 8
	}
}

/* kexInit builds the client key exchange init data */
func (sc *sshConn) kexInit() []byte {
	buf := make([]byte, 256)
	i := 16 /* first 16 bytes for cookie */
	list := []string{"kex", "pky", "enc", "enc", "mac", "mac", "cpr", "cpr", "lan", "lan"}
	for _, item := range list {
		str := strings.Join(sc.algo[item], ",")
		SSHEndian.PutUint32(buf[i:], uint32(len(str)))
		i += copy(buf[i+4:], str) + 4
	}
	/* 1 byte for first_kex_packet_follows and 4 bytes reserved */
	return buf[:i+5]
}

/* selectAlgo handles the server key exchange init data, and selects algorithms */
func (sc *sshConn) selectAlgo(data []byte) bool {
	var flag bool
	var str string
	var length, i int
	var list = []string{"kex", "pky", "enc", "enc", "mac", "mac", "cpr", "cpr", "lan", "lan"}
	for _, item := range list {
		if len(data) < i+4 {
			sc.PrintError("invalid server key exchange init packet")
			return false
		}

		flag = false
		/* ignore languague option for no preference */
		if item != "lan" {
			length = int(SSHEndian.Uint32(data[i:]))
			if len(data) < i+length {
				sc.PrintError("invalid server key exchange init packet")
				return false
			}
			str = string(data[i+4 : i+length+4])

			for _, alg := range sc.algo[item] {
				if strings.Contains(str, alg) {
					flag = true
					sc.algo[item] = []string{alg}
					break
				}
			}
			if !flag {
				sc.PrintError("Unsupported %s algorithms: %s", item, str)
				return false
			}
			i += length
		}
		i += 4
	}
	return true
}

/************************************************************************
 *                            Handle Packets                            *
 ************************************************************************/

/* read protocol version from the server */
func (sc *sshConn) readVersion() error {
	var buf []byte

	if len(sc.raw) > 0 {
		buf = sc.raw
	} else {
		buf = make([]byte, 2048)
		n, err := sc.Read(buf)
		if err != nil {
			return err
		}
		buf = buf[:n]
	}

	/* */
	i := bytes.Index(buf, []byte{'\r', '\n'})
	if i == -1 {
		return errors.New("invalid SSH handshake packet")
	}

	sc.message = buf[:i]
	sc.raw = buf[i+2:]
	return nil
}

/* read message from the server */
func (sc *sshConn) read() error {
	var buf []byte

	if len(sc.raw) > 0 {
		buf = sc.raw
	} else {
		buf = make([]byte, 2048)
		n, err := sc.Read(buf)
		if err != nil {
			return err
		}
		buf = buf[:n]
	}

	if len(buf) < 4 {
		return errors.New("invalid SSH packet size")
	}

	/* 4-byte packet length (excluding first 4 bytes and mac) */
	size := int(SSHEndian.Uint32(buf[:4])) + 4
	if len(buf) < size {
		return errors.New("invalid SSH packet size")
	}

	sc.message = buf[5 : size-int(buf[4])]
	sc.raw = buf[size:]

	return nil
}

/* send protocol version to the server */
func (sc *sshConn) writeVersion(data []byte) error {
	return sc.Write(data)
}

/* send request to the server */
func (sc *sshConn) write(code byte, data []byte) error {

	/* paddings */
	blocksize := sc.blockSize(sc.algo["enc"][0])
	padsize := blocksize - (len(data)+6)%blocksize
	if padsize < 4 {
		padsize += blocksize
	}

	/* payload */
	length := 2 + len(data) + padsize
	buf := make([]byte, length+4)
	SSHEndian.PutUint32(buf, uint32(length))
	buf[4] = byte(padsize)
	buf[5] = code
	copy(buf[6:], data)

	return sc.Write(buf)

}
