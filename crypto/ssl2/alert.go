// Copyright 2026 The runZero contributors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ssl2

import "fmt"

// ErrorCode is the 2-octet error value carried in an SSL 2.0 ERROR
// message (handshake message type 0). Reference: "The SSL Protocol" §1.5.1.
type ErrorCode uint16

const (
	ErrNoCipher        ErrorCode = 0x0001
	ErrNoCertificate   ErrorCode = 0x0002
	ErrBadCertificate  ErrorCode = 0x0004
	ErrUnsupportedCert ErrorCode = 0x0006
)

// String returns the canonical SSL 2.0 error name.
func (e ErrorCode) String() string {
	switch e {
	case ErrNoCipher:
		return "NO-CIPHER-ERROR"
	case ErrNoCertificate:
		return "NO-CERTIFICATE-ERROR"
	case ErrBadCertificate:
		return "BAD-CERTIFICATE-ERROR"
	case ErrUnsupportedCert:
		return "UNSUPPORTED-CERTIFICATE-TYPE-ERROR"
	}
	return fmt.Sprintf("UNKNOWN-ERROR(0x%04x)", uint16(e))
}

// Error implements the error interface so an [ErrorCode] returned from a
// peer can be propagated directly.
func (e ErrorCode) Error() string {
	return "ssl2: peer sent " + e.String()
}
