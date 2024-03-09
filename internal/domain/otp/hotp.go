package otp

import (
	"crypto/hmac"
	"encoding/binary"
	"log"
	"math"
	"strconv"
	"strings"
)

// Hotp HMAC-based One-Time Password
type Hotp struct {
	config *Config
}

// GenerateCode uses a counter and secret value to create a passcode.
func (h *Hotp) GenerateCode(counter uint64) (passcode string, err error) {
	//Set default value 6
	if h.config.Digits == DigitsNull {
		h.config.Digits = DigitsSix
	}

	secret := string(h.config.Secret)
	// As noted in issue #24 Google has started producing base32 in lower case,
	// but the StdEncoding (and the RFC), expect a dictionary of only upper case letters.
	secret = strings.ToUpper(secret)

	buf := make([]byte, 8)
	mac := hmac.New(h.config.Algorithm.Hash, h.config.Secret)
	binary.BigEndian.PutUint64(buf, counter)

	// debug
	log.Printf("counter=%v\n", counter)
	log.Printf("buf=%v\n", buf)

	mac.Write(buf)
	sum := mac.Sum(nil)

	// dynamic truncation in RFC 4226
	// http://tools.ietf.org/html/rfc4226#section-5.4
	offset := sum[len(sum)-1] & 0xf
	value := int64(((int(sum[offset]) & 0x7f) << 24) |
		((int(sum[offset+1] & 0xff)) << 16) |
		((int(sum[offset+2] & 0xff)) << 8) |
		(int(sum[offset+3]) & 0xff))

	mod := int(value % int64(math.Pow10(h.config.Digits.Value())))

	// debug
	log.Printf("offset=%v\n", offset)
	log.Printf("value=%v\n", value)
	log.Printf("moded=%v\n", mod)

	return strconv.Itoa(mod), nil
}
