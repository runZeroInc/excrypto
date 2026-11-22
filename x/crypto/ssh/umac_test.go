package ssh

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"
)

// RFC 4418 appendix: K "abcdefghijklmnop", nonce "bcdefghi".
func TestUMACVectors(t *testing.T) {
	key, nonce := []byte("abcdefghijklmnop"), []byte("bcdefghi")
	vectors := []struct {
		msg           string
		t32, t64, t96 string
		long          bool
	}{
		{"", "113145FB", "6E155FAD26900BE1", "32FEDB100C79AD58F07FF764", false},
		{strings.Repeat("a", 3), "3B91D102", "44B5CB542F220104", "185E4FE905CBA7BD85E4C2DC", false},
		{strings.Repeat("a", 1<<10), "599B350B", "26BF2F5D60118BD9", "7A54ABE04AF82D60FB298C3C", false},
		{strings.Repeat("a", 1<<15), "58DCF532", "27F8EF643B0D118D", "7B136BD911E4B734286EF2BE", false},
		{strings.Repeat("a", 1<<20), "DB6364D1", "A4477E87E9F55853", "F8ACFA3AC31CFEEA047F7B11", false},
		// Errata 3507 corrects this row.
		{strings.Repeat("a", 1<<25), "85EE5CAE", "FACA46F856E9B45F", "A621C2457C0012E64F3FDAE9", true},
		{"abc", "ABF3A3A0", "D4D7B9F6BD4FBFCF", "883C3D4B97A61976FFCF2323", false},
		{strings.Repeat("abc", 500), "ABEB3C8B", "D4CF26DDEFD5C01A", "8824A260C53C66A36C9260A6", false},
	}
	for _, v := range vectors {
		if v.long && testing.Short() {
			continue
		}
		for _, c := range []struct {
			taglen int
			want   string
		}{{4, v.t32}, {8, v.t64}, {12, v.t96}} {
			got := umacTag(newUMACKey(key, c.taglen), []byte(v.msg), nonce)
			if !strings.EqualFold(hex.EncodeToString(got), c.want) {
				t.Errorf("len %d taglen %d: got %X want %s", len(v.msg), c.taglen, got, c.want)
			}
		}
	}
}

// The hash.Hash form takes the sequence number as the nonce's low half.
func TestUMACHashNonce(t *testing.T) {
	key := []byte("abcdefghijklmnop")
	for _, taglen := range []int{8, 16} {
		h := newUMAC(key, taglen)
		h.Write([]byte{0, 0, 1, 2})
		h.Write([]byte("packet"))
		got := h.Sum(nil)
		want := umacTag(newUMACKey(key, taglen), []byte("packet"), []byte{0, 0, 0, 0, 0, 0, 1, 2})
		if !bytes.Equal(got, want) || len(got) != taglen {
			t.Errorf("taglen %d: %x != %x", taglen, got, want)
		}
		h.Reset()
		h.Write([]byte{0, 0, 1, 2, 'p', 'a', 'c', 'k', 'e', 't'})
		if again := h.Sum(nil); !bytes.Equal(again, want) {
			t.Errorf("taglen %d after reset: %x", taglen, again)
		}
	}
}
