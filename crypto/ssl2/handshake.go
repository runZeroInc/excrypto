// Copyright 2026 The runZero contributors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ssl2

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// ClientHello is the SSL 2.0 CLIENT-HELLO handshake message.
//
//	struct {
//	    uint8  msg_type;            // == 1
//	    uint16 version;             // == 0x0002
//	    uint16 cipher_specs_length;
//	    uint16 session_id_length;
//	    uint16 challenge_length;    // 16..32
//	    opaque cipher_specs[cipher_specs_length];
//	    opaque session_id[session_id_length];
//	    opaque challenge[challenge_length];
//	} ClientHello;
type ClientHello struct {
	Version     uint16
	CipherSpecs []CipherKind
	SessionID   []byte
	Challenge   []byte
}

// Marshal returns the wire encoding (excluding the record header) of the
// CLIENT-HELLO message.
func (c *ClientHello) Marshal() ([]byte, error) {
	if len(c.Challenge) < 16 || len(c.Challenge) > 32 {
		return nil, fmt.Errorf("ssl2: CLIENT-HELLO challenge length %d outside [16,32]", len(c.Challenge))
	}
	if len(c.CipherSpecs) == 0 {
		return nil, errors.New("ssl2: CLIENT-HELLO must offer at least one cipher")
	}
	if len(c.SessionID) != 0 && len(c.SessionID) != 16 {
		return nil, fmt.Errorf("ssl2: CLIENT-HELLO session_id length must be 0 or 16, got %d", len(c.SessionID))
	}
	cipherBytes := 3 * len(c.CipherSpecs)
	out := make([]byte, 0, 9+cipherBytes+len(c.SessionID)+len(c.Challenge))
	out = append(out, byte(MsgClientHello))
	out = binary.BigEndian.AppendUint16(out, c.Version)
	out = binary.BigEndian.AppendUint16(out, uint16(cipherBytes))
	out = binary.BigEndian.AppendUint16(out, uint16(len(c.SessionID)))
	out = binary.BigEndian.AppendUint16(out, uint16(len(c.Challenge)))
	for _, spec := range c.CipherSpecs {
		out = append(out, byte(spec>>16), byte(spec>>8), byte(spec))
	}
	out = append(out, c.SessionID...)
	out = append(out, c.Challenge...)
	return out, nil
}

// ParseClientHello parses an SSL 2.0 CLIENT-HELLO message body (record
// payload, with the message-type octet still attached).
func ParseClientHello(payload []byte) (*ClientHello, error) {
	if len(payload) < 9 {
		return nil, errors.New("ssl2: CLIENT-HELLO truncated")
	}
	if MessageType(payload[0]) != MsgClientHello {
		return nil, fmt.Errorf("ssl2: not a CLIENT-HELLO (msg type %d)", payload[0])
	}
	c := &ClientHello{
		Version: binary.BigEndian.Uint16(payload[1:3]),
	}
	csLen := int(binary.BigEndian.Uint16(payload[3:5]))
	sidLen := int(binary.BigEndian.Uint16(payload[5:7]))
	chLen := int(binary.BigEndian.Uint16(payload[7:9]))
	if csLen%3 != 0 {
		return nil, fmt.Errorf("ssl2: cipher_specs_length %d not a multiple of 3", csLen)
	}
	if 9+csLen+sidLen+chLen > len(payload) {
		return nil, errors.New("ssl2: CLIENT-HELLO body shorter than declared")
	}
	off := 9
	c.CipherSpecs = make([]CipherKind, 0, csLen/3)
	for i := 0; i < csLen; i += 3 {
		c.CipherSpecs = append(c.CipherSpecs, CipherKind(uint32(payload[off+i])<<16|uint32(payload[off+i+1])<<8|uint32(payload[off+i+2])))
	}
	off += csLen
	if sidLen > 0 {
		c.SessionID = append([]byte(nil), payload[off:off+sidLen]...)
		off += sidLen
	}
	if chLen < 16 || chLen > 32 {
		return nil, fmt.Errorf("ssl2: CLIENT-HELLO challenge length %d outside [16,32]", chLen)
	}
	c.Challenge = append([]byte(nil), payload[off:off+chLen]...)
	return c, nil
}

// ServerHello is the SSL 2.0 SERVER-HELLO handshake message.
//
//	struct {
//	    uint8  msg_type;             // == 4
//	    uint8  session_id_hit;       // 0 (false) or 1 (true)
//	    uint8  certificate_type;     // 1 == X.509
//	    uint16 version;
//	    uint16 certificate_length;
//	    uint16 cipher_specs_length;
//	    uint16 connection_id_length; // 16..32
//	    opaque certificate[certificate_length];
//	    opaque cipher_specs[cipher_specs_length];
//	    opaque connection_id[connection_id_length];
//	} ServerHello;
type ServerHello struct {
	SessionIDHit    bool
	CertificateType CertType
	Version         uint16
	Certificate     []byte
	CipherSpecs     []CipherKind
	ConnectionID    []byte
}

// Marshal returns the wire encoding of the SERVER-HELLO message.
func (s *ServerHello) Marshal() ([]byte, error) {
	if len(s.ConnectionID) < 16 || len(s.ConnectionID) > 32 {
		return nil, fmt.Errorf("ssl2: SERVER-HELLO connection_id length %d outside [16,32]", len(s.ConnectionID))
	}
	cipherBytes := 3 * len(s.CipherSpecs)
	out := make([]byte, 0, 11+len(s.Certificate)+cipherBytes+len(s.ConnectionID))
	out = append(out, byte(MsgServerHello))
	if s.SessionIDHit {
		out = append(out, 1)
	} else {
		out = append(out, 0)
	}
	out = append(out, byte(s.CertificateType))
	out = binary.BigEndian.AppendUint16(out, s.Version)
	out = binary.BigEndian.AppendUint16(out, uint16(len(s.Certificate)))
	out = binary.BigEndian.AppendUint16(out, uint16(cipherBytes))
	out = binary.BigEndian.AppendUint16(out, uint16(len(s.ConnectionID)))
	out = append(out, s.Certificate...)
	for _, spec := range s.CipherSpecs {
		out = append(out, byte(spec>>16), byte(spec>>8), byte(spec))
	}
	out = append(out, s.ConnectionID...)
	return out, nil
}

// ParseServerHello parses a SERVER-HELLO record payload (with the
// message-type octet still attached).
func ParseServerHello(payload []byte) (*ServerHello, error) {
	if len(payload) < 11 {
		return nil, errors.New("ssl2: SERVER-HELLO truncated")
	}
	if MessageType(payload[0]) != MsgServerHello {
		return nil, fmt.Errorf("ssl2: not a SERVER-HELLO (msg type %d)", payload[0])
	}
	s := &ServerHello{
		SessionIDHit:    payload[1] != 0,
		CertificateType: CertType(payload[2]),
		Version:         binary.BigEndian.Uint16(payload[3:5]),
	}
	certLen := int(binary.BigEndian.Uint16(payload[5:7]))
	csLen := int(binary.BigEndian.Uint16(payload[7:9]))
	connLen := int(binary.BigEndian.Uint16(payload[9:11]))
	if csLen%3 != 0 {
		return nil, fmt.Errorf("ssl2: cipher_specs_length %d not a multiple of 3", csLen)
	}
	if 11+certLen+csLen+connLen > len(payload) {
		return nil, errors.New("ssl2: SERVER-HELLO body shorter than declared")
	}
	off := 11
	if certLen > 0 {
		s.Certificate = append([]byte(nil), payload[off:off+certLen]...)
		off += certLen
	}
	s.CipherSpecs = make([]CipherKind, 0, csLen/3)
	for i := 0; i < csLen; i += 3 {
		s.CipherSpecs = append(s.CipherSpecs, CipherKind(uint32(payload[off+i])<<16|uint32(payload[off+i+1])<<8|uint32(payload[off+i+2])))
	}
	off += csLen
	if connLen < 16 || connLen > 32 {
		return nil, fmt.Errorf("ssl2: SERVER-HELLO connection_id length %d outside [16,32]", connLen)
	}
	s.ConnectionID = append([]byte(nil), payload[off:off+connLen]...)
	return s, nil
}

// ClientMasterKey is the SSL 2.0 CLIENT-MASTER-KEY handshake message.
//
//	struct {
//	    uint8  msg_type;                         // == 2
//	    uint24 cipher_kind;                      // selected CIPHER-KIND
//	    uint16 clear_key_length;
//	    uint16 encrypted_key_length;
//	    uint16 key_arg_length;
//	    opaque clear_key[clear_key_length];
//	    opaque encrypted_key[encrypted_key_length];
//	    opaque key_arg[key_arg_length];
//	} ClientMasterKey;
type ClientMasterKey struct {
	CipherKind   CipherKind
	ClearKey     []byte
	EncryptedKey []byte
	KeyArg       []byte
}

// Marshal returns the wire encoding of CLIENT-MASTER-KEY.
func (c *ClientMasterKey) Marshal() ([]byte, error) {
	out := make([]byte, 0, 10+len(c.ClearKey)+len(c.EncryptedKey)+len(c.KeyArg))
	out = append(out, byte(MsgClientMasterKey))
	out = append(out, byte(c.CipherKind>>16), byte(c.CipherKind>>8), byte(c.CipherKind))
	out = binary.BigEndian.AppendUint16(out, uint16(len(c.ClearKey)))
	out = binary.BigEndian.AppendUint16(out, uint16(len(c.EncryptedKey)))
	out = binary.BigEndian.AppendUint16(out, uint16(len(c.KeyArg)))
	out = append(out, c.ClearKey...)
	out = append(out, c.EncryptedKey...)
	out = append(out, c.KeyArg...)
	return out, nil
}

// ParseClientMasterKey parses a CLIENT-MASTER-KEY record payload.
func ParseClientMasterKey(payload []byte) (*ClientMasterKey, error) {
	if len(payload) < 10 {
		return nil, errors.New("ssl2: CLIENT-MASTER-KEY truncated")
	}
	if MessageType(payload[0]) != MsgClientMasterKey {
		return nil, fmt.Errorf("ssl2: not a CLIENT-MASTER-KEY (msg type %d)", payload[0])
	}
	c := &ClientMasterKey{
		CipherKind: CipherKind(uint32(payload[1])<<16 | uint32(payload[2])<<8 | uint32(payload[3])),
	}
	clearLen := int(binary.BigEndian.Uint16(payload[4:6]))
	encLen := int(binary.BigEndian.Uint16(payload[6:8]))
	argLen := int(binary.BigEndian.Uint16(payload[8:10]))
	if 10+clearLen+encLen+argLen > len(payload) {
		return nil, errors.New("ssl2: CLIENT-MASTER-KEY body shorter than declared")
	}
	off := 10
	c.ClearKey = append([]byte(nil), payload[off:off+clearLen]...)
	off += clearLen
	c.EncryptedKey = append([]byte(nil), payload[off:off+encLen]...)
	off += encLen
	c.KeyArg = append([]byte(nil), payload[off:off+argLen]...)
	return c, nil
}

// ServerError represents an ERROR handshake message (msg_type 0).
type ServerError struct {
	Code ErrorCode
}

// Marshal encodes an ERROR message.
func (e *ServerError) Marshal() []byte {
	return []byte{byte(MsgError), byte(e.Code >> 8), byte(e.Code)}
}

// ParseError parses an ERROR record payload.
func ParseError(payload []byte) (*ServerError, error) {
	if len(payload) < 3 {
		return nil, errors.New("ssl2: ERROR message truncated")
	}
	if MessageType(payload[0]) != MsgError {
		return nil, fmt.Errorf("ssl2: not an ERROR message (msg type %d)", payload[0])
	}
	return &ServerError{Code: ErrorCode(binary.BigEndian.Uint16(payload[1:3]))}, nil
}

// ClientFinished, ServerVerify, ServerFinished and the certificate-request
// pair are simple opaque-payload messages. We expose minimal types for
// completeness so callers can drive a full handshake skeleton.

// ClientFinished is CLIENT-FINISHED (msg_type 3): a single connection-id
// echo encrypted with the client write key. We do not implement encryption,
// but we expose Marshal/Parse over the cleartext body for tests.
type ClientFinished struct{ ConnectionID []byte }

func (m *ClientFinished) Marshal() []byte {
	return append([]byte{byte(MsgClientFinished)}, m.ConnectionID...)
}

func ParseClientFinished(payload []byte) (*ClientFinished, error) {
	if len(payload) < 1 || MessageType(payload[0]) != MsgClientFinished {
		return nil, errors.New("ssl2: not a CLIENT-FINISHED")
	}
	return &ClientFinished{ConnectionID: append([]byte(nil), payload[1:]...)}, nil
}

// ServerVerify is SERVER-VERIFY (msg_type 5): the server's encryption of
// the client's CHALLENGE.
type ServerVerify struct{ Challenge []byte }

func (m *ServerVerify) Marshal() []byte {
	return append([]byte{byte(MsgServerVerify)}, m.Challenge...)
}

func ParseServerVerify(payload []byte) (*ServerVerify, error) {
	if len(payload) < 1 || MessageType(payload[0]) != MsgServerVerify {
		return nil, errors.New("ssl2: not a SERVER-VERIFY")
	}
	return &ServerVerify{Challenge: append([]byte(nil), payload[1:]...)}, nil
}

// ServerFinished is SERVER-FINISHED (msg_type 6): a fresh session-id the
// client may resume with.
type ServerFinished struct{ SessionID []byte }

func (m *ServerFinished) Marshal() []byte {
	return append([]byte{byte(MsgServerFinished)}, m.SessionID...)
}

func ParseServerFinished(payload []byte) (*ServerFinished, error) {
	if len(payload) < 1 || MessageType(payload[0]) != MsgServerFinished {
		return nil, errors.New("ssl2: not a SERVER-FINISHED")
	}
	return &ServerFinished{SessionID: append([]byte(nil), payload[1:]...)}, nil
}
