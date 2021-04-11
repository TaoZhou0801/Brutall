// scram.go implements SCRAM authentication WITHOUT channel binding.
//
// Usage:
// 		sc := NewSCRAM("", "user", "pencil", sha1.New, nil)
//
// 		req := sc.WriteClientFirstMessage()
//
// 		... // send req to and receive resp from the server
//
//		err := sc.ReadServerFirstMessage(resp)
//
// 		... // process error
//
// 		req = sc.WriteClientFinalMessage()
//
// 		... // send req to and receive resp from the server
//
// 		mes, err := sc.ReadServerFinalMessage(resp)
//
// 		... // process error
//
// Reference:
// 	RFC 5802 - SASL SCRAM-SHA-1
// 	RFC 7677 - SASL SCRAM-SHA-256

package main

import (
	"bytes"
	"crypto/hmac"
	"encoding/base64"
	"fmt"
	"hash"
	"math/rand"
	"strconv"
	"strings"
	"time"
)

type SCRAM struct {
	// input data
	authzid  string // UTF-8 authorization id, with ',' and '=' replaced by '=2C', '=3D'
	username string // UTF-8 username, with ',' and '=' replaced by '=2C', '=3D'
	password string // UTF-8 password
	hash     func() hash.Hash

	// internal data
	nonce      []byte // client side generated random data
	salt       []byte // sent by server
	iter       int    // iteration count from server
	saltedpass []byte // saved for second use
	authmes    []byte // AuthMessage := client-first-message-bare + "," + server-first-message + "," + client-final-message-without-proof*/
	stage      int    // 0-uninitiatied, 1-built first message, 2-built final message
}

// note: a 20-byte nonce will be generated if nothing is passed to nonce
func NewSCRAM(authzid, username, password string, hash func() hash.Hash, nonce []byte) *SCRAM {
	replacer := strings.NewReplacer(",", "=2C", "=", "=3D")
	return &SCRAM{
		authzid:  replacer.Replace(authzid),
		username: replacer.Replace(username),
		password: password,
		hash:     hash,
		nonce:    nonce,
	}
}

// tells which stage we are in
// 0-uninitiatied, 1-built first message, 2-built final message
func (sc *SCRAM) Stage() int {
	if sc == nil {
		return 0
	}
	return sc.stage
}

/************************************************************************
 *                            Handle Packets                            *
 ************************************************************************/

// client-first-message = gs2-header client-first-message-bare
func (sc *SCRAM) ClientFirstMessage() []byte {
	// generate client-side nonce
	if sc.nonce == nil {
		sc.generateNonce(20)
	}

	// save a copy of client-first-message-bare
	buf := sc.getClientFisrtBare()
	sc.authmes = make([]byte, len(buf))
	copy(sc.authmes, buf)

	sc.stage = 1
	return append(sc.getGS2Header(), buf...)
}

// server-first-message = [reserved-mext ","] nonce "," salt "," iteration-count ["," extensions]
func (sc *SCRAM) ServerFirstMessage(message []byte) error {
	items := bytes.Split(message, []byte{','})
	if len(items) < 3 {
		return fmt.Errorf("invalid server-first-message %q", message)
	}

	if !bytes.HasPrefix(items[0], []byte{'r', '='}) || !bytes.HasPrefix(items[0][2:], sc.nonce) {
		return fmt.Errorf("server-first-message: invalid nonce %q", items[0])
	}
	if !bytes.HasPrefix(items[1], []byte{'s', '='}) {
		return fmt.Errorf("server-first-message: invalid salt %q", items[1])
	}
	if !bytes.HasPrefix(items[2], []byte{'i', '='}) {
		return fmt.Errorf("server-first-message: invalid iteration count %q", items[2])
	}

	sc.nonce = items[0][2:]
	// base64 decode salt
	sc.salt = make([]byte, base64.StdEncoding.DecodedLen(len(items[1][2:])))
	n, err := base64.StdEncoding.Decode(sc.salt, items[1][2:])
	if err != nil {
		return fmt.Errorf("server-first-message: invalid base64 salt value %q", items[1][2:])
	}
	sc.salt = sc.salt[:n]
	// read iteration count
	sc.iter, err = strconv.Atoi(string(items[2][2:]))
	if err != nil {
		return fmt.Errorf("server-first-message: invalid iteration count value %q", items[2][2:])
	}

	// save a copy of server-first-message
	sc.authmes = append(sc.authmes, ',')
	sc.authmes = append(sc.authmes, message...)

	return nil
}

// client-final-message = channel-binding "," nonce ["," extensions] "," proof
func (sc *SCRAM) ClientFinalMessage() []byte {
	sc.generateSaltedPass()
	pre := sc.getClientFinalNoProof()

	// save a copy of client-final-message-without-proof
	sc.authmes = append(sc.authmes, ',')
	sc.authmes = append(sc.authmes, pre...)
	proof := sc.getClientProof()

	// build payload
	buf := make([]byte, len(pre)+base64.StdEncoding.EncodedLen(len(proof))+3)
	copy(buf, pre)
	buf[len(pre)] = ','
	buf[len(pre)+1] = 'p'
	buf[len(pre)+2] = '='
	base64.StdEncoding.Encode(buf[len(pre)+3:], proof)

	sc.stage = 2
	return buf
}

// server-final-message = (server-error / verifier) ["," extensions]
func (sc *SCRAM) ServerFinalMessage(message []byte) ([]byte, error) {
	items := bytes.Split(message, []byte{','})
	if bytes.HasPrefix(items[0], []byte{'v', '='}) { // verifier
		if string(items[0][2:]) == base64.StdEncoding.EncodeToString(sc.getServerSignature()) {
			return nil, nil // server verified
		} else {
			return nil, fmt.Errorf("server-final-message: invalid verifier")
		}
	} else if bytes.HasPrefix(items[0], []byte{'e', '='}) {
		return items[0][2:], nil // server error message
	} else {
		return nil, fmt.Errorf("invalid server-final-message %q", message)
	}
}

/************************************************************************
 *                            Helper Methods                            *
 ************************************************************************/

// gs2-header = gs2-cbind-flag "," [ authzid ] ","
// gs2-cbind-flag = 'n' (no channel binding)
func (sc *SCRAM) getGS2Header() []byte {
	length := 3
	if len(sc.authzid) > 0 {
		length += len(sc.authzid) + 2
	}

	buf := make([]byte, length)
	buf[0] = 'n'
	buf[1] = ','
	if len(sc.authzid) > 0 {
		buf[2] = 'a'
		buf[3] = '='
		copy(buf[4:], sc.authzid)
	}
	buf[length-1] = ','

	return buf
}

// client-first-message-bare = [reserved-mext ","] username "," nonce ["," extensions]
func (sc *SCRAM) getClientFisrtBare() []byte {
	buf := make([]byte, 5+len(sc.username)+len(sc.nonce))
	buf[0] = 'n'
	buf[1] = '='
	index := copy(buf[2:], sc.username) + 2
	buf[index] = ','
	buf[index+1] = 'r'
	buf[index+2] = '='
	copy(buf[index+3:], sc.nonce)
	return buf
}

// client-final-message-without-proof = channel-binding "," nonce ["," extensions]
// channel-binding = "c=" base64(gs2-header [ cbind-data ])
func (sc *SCRAM) getClientFinalNoProof() []byte {
	header := sc.getGS2Header()
	base64len := base64.StdEncoding.EncodedLen(len(header))
	buf := make([]byte, base64len+len(sc.nonce)+5)
	buf[0] = 'c'
	buf[1] = '='
	base64.StdEncoding.Encode(buf[2:], sc.getGS2Header())
	buf[base64len+2] = ','
	buf[base64len+3] = 'r'
	buf[base64len+4] = '='
	copy(buf[base64len+5:], sc.nonce)
	return buf
}

/************************************************************************
 *                               Utility                                *
 ************************************************************************/

// generate a random alphanumeric byte slice
func (sc *SCRAM) generateNonce(size int) {
	sc.nonce = make([]byte, size)
	alnum := "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	rand.Seed(time.Now().UnixNano())
	for index := range sc.nonce {
		sc.nonce[index] = alnum[rand.Intn(len(alnum))]
	}
}

// SaltedPassword := Hi(Normalize(password), salt, i)
// Hi(str, salt, i):
//     U1 := HMAC(str, salt + INT(1))
//     U2 := HMAC(str, U1)
//     ...
//     Ui-1 := HMAC(str, Ui-2)
//     Ui := HMAC(str, Ui-1)
//     Hi := U1 XOR U2 XOR ... XOR Ui
func (sc *SCRAM) generateSaltedPass() {
	hm := hmac.New(sc.hash, []byte(sc.password))
	hm.Write(sc.salt)
	hm.Write([]byte{0, 0, 0, 1})
	temp := hm.Sum(nil)
	sc.saltedpass = make([]byte, len(temp))
	copy(sc.saltedpass, temp)
	for i := 1; i < sc.iter; i++ {
		hm.Reset()
		hm.Write(temp)
		temp = hm.Sum(nil)
		for j, val := range temp {
			sc.saltedpass[j] ^= val
		}
	}
}

// generate ClientProof
func (sc *SCRAM) getClientProof() []byte {
	// ClientKey := HMAC(SaltedPassword, "Client Key")
	hm := hmac.New(sc.hash, sc.saltedpass)
	hm.Write([]byte("Client Key"))
	clientkey := hm.Sum(nil)
	// StoredKey := H(ClientKey)
	hash := sc.hash()
	hash.Write(clientkey)
	storedkey := hash.Sum(nil)
	// ClientSignature := HMAC(StoredKey, AuthMessage)
	hm = hmac.New(sc.hash, storedkey)
	hm.Write(sc.authmes)
	res := hm.Sum(nil)

	// ClientProof := ClientKey XOR ClientSignature
	for i, val := range clientkey {
		res[i] ^= val
	}

	return res
}

// generate ServerSignature
func (sc *SCRAM) getServerSignature() []byte {
	// ServerKey := HMAC(SaltedPassword, "Server Key")
	hm := hmac.New(sc.hash, sc.saltedpass)
	hm.Write([]byte("Server Key"))
	serverkey := hm.Sum(nil)
	// ServerSignature := HMAC(ServerKey, AuthMessage)
	hm = hmac.New(sc.hash, serverkey)
	hm.Write(sc.authmes)
	return hm.Sum(nil)
}
