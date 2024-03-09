package otp

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"errors"
	"hash"
)

type Config struct {
	// Number of seconds a TOTP hash is valid for. Defaults to 30 seconds.
	Period uint
	// Size in size of the generated Secret. Defaults to 20 bytes.
	SecretSize uint
	// Secret to store. Defaults to a randomly generated secret of SecretSize.  You should generally leave this empty.
	Secret []byte
	// Periods before or after the current time to allow.  Value of 1 allows up to Period
	// of either side of the specified time.  Defaults to 0 allowed skews.  Values greater
	// than 1 are likely sketchy.
	Skew uint
	// Digits represents the number of digits present in the user's OTP passcode. Six and Eight are the most common values.
	Digits Digits
	// Algorithm to use for HMAC. Defaults to SHA1.
	Algorithm Algorithm
}

// Digits represents the number of digits present in the user's OTP passcode. Six or Eight
type Digits int

const (
	DigitsNull  Digits = 0
	DigitsSix   Digits = 6
	DigitsEight Digits = 8
)

func (d *Digits) Value() int {
	switch *d {
	case DigitsEight:
		return 8
	case DigitsSix:
		return 6
	}
	return 0
}

// Algorithm represents the hashing function to use in the HMAC operation needed for OTPs.
type Algorithm int

const (
	AlgorithmNull Algorithm = iota
	// AlgorithmSHA1 should be used for iOS & android with Google Authenticator.
	AlgorithmSHA1
	AlgorithmSHA256
	AlgorithmSHA512
	AlgorithmMD5
)

var ErrValidateInputInvalidLength = errors.New("input length unexpected")

// Hash .
func (a Algorithm) Hash() hash.Hash {
	switch a {
	case AlgorithmNull:
		return sha1.New()
	case AlgorithmSHA1:
		return sha1.New()
	case AlgorithmSHA256:
		return sha256.New()
	case AlgorithmSHA512:
		return sha512.New()
	case AlgorithmMD5:
		return md5.New()
	default:
		return sha1.New()
		//panic("unhandled default case")
	}
}
