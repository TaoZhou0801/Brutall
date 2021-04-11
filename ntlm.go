// ntlm.go gives a minimal implementation of NTLMv1.
//
// Reference:
//		[MS-LNMP]

package main

import (
	"crypto/des"
	"crypto/md5"
	"encoding/binary"
	"strings"
	"unicode/utf16"
	"unicode/utf8"

	"golang.org/x/crypto/md4"
)

var ntlmEndian = binary.LittleEndian

// ntlm NEGOTIATE_MESSAGE
func NtlmNegotiate(domain, workstation string) []byte {
	buf := make([]byte, 40+len(domain)+len(workstation))
	copy(buf, "NTLMSSP\x00")
	buf[8] = 0x01  // message type: negotiate
	buf[12] = 0x07 // minimal flags
	buf[13] = 0xb2

	i := 40 // offset
	i += putField(buf, []byte(domain), 16, i)
	putField(buf, []byte(workstation), 24, i)

	return buf
}

// ntlm AUTHENTICATE_MESSAGE, where resp holds CHALLENGE_MESSAGE
func NtlmAuthenticate(resp []byte, domain, workstation, user, pass string) []byte {
	flags := resp[20:24] // server negotiate flags
	schal := resp[24:32] // server challenge

	cchal := []byte{0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa} // client challenge

	var ntcr, lmcr []byte // NtChallengeResponse, LmChallengeResponse
	if flags[2]&0x08 == 0 {
		ntcr = desl(ntowfv1(pass), schal)
		lmcr = desl(lmowfv1(pass), schal)
	} else {
		h := md5.New()
		h.Write(schal)
		h.Write(cchal)
		ntcr = desl(ntowfv1(pass), h.Sum(nil)[:8])
		lmcr = make([]byte, 24)
		copy(lmcr, cchal)
	}

	buf := make([]byte, 120+utf8.RuneCountInString(domain)*2+
		utf8.RuneCountInString(workstation)*2+utf8.RuneCountInString(user)*2)
	copy(buf, "NTLMSSP\x00")
	buf[8] = 0x03           // message type: authenticate
	copy(buf[60:64], flags) // negotiate flag

	i := 72
	i += putField(buf, encodeUTF16(domain), 28, i)
	i += putField(buf, encodeUTF16(user), 36, i)
	i += putField(buf, encodeUTF16(workstation), 44, i)
	i += putField(buf, lmcr, 12, i) // LmChallengeResponse field
	putField(buf, ntcr, 20, i)      // NtChallengeResponse field

	return buf
}

// set field and append data
func putField(buf, data []byte, fpos, dpos int) int {
	if len(data) == 0 {
		return 0
	}
	ntlmEndian.PutUint16(buf[fpos:fpos+2], uint16(len(data))) // NameLen
	copy(buf[fpos+2:fpos+4], buf[fpos:fpos+2])                // MaxNameLen
	ntlmEndian.PutUint32(buf[fpos+4:fpos+8], uint32(dpos))    // NameBufferOffset
	return copy(buf[dpos:], data)                             // payload
}

// Define NTOWFv1(Passwd User UserDom) as MD4(UNICODE(Passwd))
func ntowfv1(pass string) []byte {
	hash := md4.New()
	hash.Write(encodeUTF16(pass))
	return hash.Sum(nil)
}

// Define LMOWFv1(Passwd, User, UserDom) as
// ConcatenationOf( DES( UpperCase( Passwd)[0..6],"KGS!@#$%"),
// DES( UpperCase( Passwd)[7..13],"KGS!@#$%"))
func lmowfv1(pass string) []byte {
	pass = strings.ToUpper(pass)
	out := make([]byte, 16)

	dkey := make([]byte, 7)
	copy(dkey, pass)
	block, _ := des.NewCipher(deskey(dkey))
	block.Encrypt(out, []byte("KGS!@#$%"))

	dkey = make([]byte, 7)
	if len(pass) > 7 {
		copy(dkey, pass[7:])
	}
	block, _ = des.NewCipher(deskey(dkey))
	block.Encrypt(out[8:], []byte("KGS!@#$%"))

	return out
}

// ConcatenationOf( DES(K[0..6], D), DES(K[7..13], D),
// DES(ConcatenationOf(K[14..15], Z(5)), D) ), with 16-byte key and 8-byte data
func desl(key, data []byte) []byte {
	out := make([]byte, 24)

	dkey := make([]byte, 7)
	copy(dkey, key)
	block, _ := des.NewCipher(deskey(dkey))
	block.Encrypt(out, data)

	copy(dkey, key[7:])
	block, _ = des.NewCipher(deskey(dkey))
	block.Encrypt(out[8:], data)

	dkey = make([]byte, 7)
	copy(dkey, key[14:])
	block, _ = des.NewCipher(deskey(dkey))
	block.Encrypt(out[16:], data)

	return out
}

// encode Go's UTF-8 string as UTF-16 byte slice
func encodeUTF16(in string) []byte {
	if len(in) == 0 {
		return nil
	}
	tmp := utf16.Encode([]rune(in))
	out := make([]byte, len(tmp)*2)
	for i, v := range tmp {
		ntlmEndian.PutUint16(out[i*2:], v)
	}
	return out
}

// decode UTF-16 byte slice to Go's UTF-8 string
func decodeUTF16(buf []byte) string {
	if len(buf) == 0 {
		return ""
	}
	out := make([]uint16, len(buf)/2)
	for i := range out {
		out[i] = ntlmEndian.Uint16(buf)
		buf = buf[2:]
	}
	return string(utf16.Decode(out))
}

// build 8-byte des key from 7 bytes input
func deskey(in []byte) []byte {
	out := make([]byte, 8)

	out[0] = in[0] >> 1
	out[1] = (in[0]&0x01)<<6 | in[1]>>2
	out[2] = (in[1]&0x03)<<5 | in[2]>>3
	out[3] = (in[2]&0x07)<<4 | in[3]>>4
	out[4] = (in[3]&0x0F)<<3 | in[4]>>5
	out[5] = (in[4]&0x1F)<<2 | in[5]>>6
	out[6] = (in[5]&0x3F)<<1 | in[6]>>7
	out[7] = in[6] & 0x7F
	for i := 0; i < 8; i++ {
		out[i] = (out[i] << 1)
	}

	return out
}
