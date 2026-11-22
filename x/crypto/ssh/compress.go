package ssh

import (
	"bytes"
	"compress/zlib"
	"errors"
	"io"
	"iter"
	"sync/atomic"

	"github.com/runZeroInc/excrypto/x/crypto/ssh/internal/flate"
)

// Packet compression (RFC 4253 section 6.2). "zlib" runs from the NEWKEYS
// that selects it; "zlib@openssh.com" waits for USERAUTH_SUCCESS. Each key
// change after that starts a fresh stream in each direction, as OpenSSH does.
const (
	compressionZlib    = "zlib"
	compressionDelayed = "zlib@openssh.com"
)

var errCompressedTooLarge = errors.New("ssh: decompressed packet too large")

// keyChange carries a new cipher and the compression negotiated with it.
type keyChange struct {
	packetCipher
	compression string
}

// compState is one direction's compression.
type compState struct {
	alg       string
	afterAuth atomic.Bool

	zw  *zlib.Writer
	out bytes.Buffer

	inf *inflater
}

func (c *compState) active() bool {
	return c.alg == compressionZlib || (c.alg == compressionDelayed && c.afterAuth.Load())
}

// rekey drops the current streams and takes the next algorithm.
func (c *compState) rekey(alg string) {
	c.alg = alg
	c.zw = nil
	c.out.Reset()
	c.stop()
}

func (c *compState) stop() {
	if c.inf != nil {
		c.inf.stop()
		c.inf = nil
	}
}

func (c *compState) compress(p []byte) ([]byte, error) {
	if c.zw == nil {
		c.out.Reset()
		c.zw = zlib.NewWriter(&c.out)
	}
	c.out.Reset()
	if _, err := c.zw.Write(p); err != nil {
		return nil, err
	}
	if err := c.zw.Flush(); err != nil {
		return nil, err
	}
	return bytes.Clone(c.out.Bytes()), nil
}

func (c *compState) decompress(p []byte) ([]byte, error) {
	if c.inf == nil {
		c.inf = newInflater()
	}
	return c.inf.feed(p)
}

// inflater runs a zlib reader as a coroutine: each packet's bytes are fed
// in and everything they decode to comes out before it asks for more. The
// adler32 trailer is never reached: the stream does not end.
type inflater struct {
	in   []byte
	out  []byte
	err  error
	next func() (struct{}, bool)
	halt func()
}

type feedReader struct {
	f     *inflater
	yield func(struct{}) bool
}

func (r *feedReader) Read(p []byte) (int, error) {
	for len(r.f.in) == 0 {
		if !r.yield(struct{}{}) {
			return 0, io.ErrClosedPipe
		}
	}
	n := copy(p, r.f.in)
	r.f.in = r.f.in[n:]
	return n, nil
}

func (r *feedReader) ReadByte() (byte, error) {
	for len(r.f.in) == 0 {
		if !r.yield(struct{}{}) {
			return 0, io.ErrClosedPipe
		}
	}
	b := r.f.in[0]
	r.f.in = r.f.in[1:]
	return b, nil
}

func newInflater() *inflater {
	f := &inflater{}
	f.next, f.halt = iter.Pull(func(yield func(struct{}) bool) {
		src := &feedReader{f: f, yield: yield}
		var h [2]byte
		if _, err := io.ReadFull(src, h[:]); err != nil {
			f.err = err
			return
		}
		if h[0]&0x0f != 8 || h[1]&0x20 != 0 || (uint16(h[0])<<8|uint16(h[1]))%31 != 0 {
			f.err = zlib.ErrHeader
			return
		}
		zr := flate.NewReader(src)
		buf := make([]byte, 4096)
		for {
			n, err := zr.Read(buf)
			f.out = append(f.out, buf[:n]...)
			if len(f.out) > maxPacket {
				f.err = errCompressedTooLarge
				return
			}
			if err != nil {
				f.err = err
				return
			}
		}
	})
	return f
}

// feed decodes one packet's compressed payload.
func (f *inflater) feed(p []byte) ([]byte, error) {
	if f.err != nil {
		return nil, f.err
	}
	f.in = p
	f.out = f.out[:0]
	if _, ok := f.next(); !ok && f.err == nil {
		f.err = io.ErrUnexpectedEOF
	}
	if f.err != nil {
		return nil, f.err
	}
	return bytes.Clone(f.out), nil
}

func (f *inflater) stop() { f.halt() }
