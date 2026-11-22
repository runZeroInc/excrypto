package ssh

import (
	"fmt"
	"hash"
	"math/big"
	"slices"

	"github.com/runZeroInc/excrypto/crypto"
	"github.com/runZeroInc/excrypto/crypto/hmac"
	"github.com/runZeroInc/excrypto/crypto/sha1"
)

// Personality makes a server present another implementation's algorithm
// negotiation: its KEXINIT name-lists verbatim and in order, its
// SSH_MSG_EXT_INFO, and the method list in its USERAUTH_FAILURE.
//
// Names this package does not implement are advertised as given. A client
// that negotiates one fails the handshake; every other client negotiates
// exactly what it would against the real implementation, because agreement
// is computed against the advertised lists.
type Personality struct {
	KeyExchanges      []string
	HostKeyAlgorithms []string
	Ciphers           []string
	MACs              []string
	Compressions      []string

	// ExtInfo is sent in order after the first NEWKEYS when the client
	// offers ext-info-c. Nil sends this package's default; empty sends none.
	ExtInfo []ExtInfoField

	// ExtInfoInAuth is sent once, before the reply to the first
	// USERAUTH_REQUEST, to a client whose EXT_INFO named
	// ext-info-in-auth@openssh.com (OpenSSH 9.6 and later do).
	ExtInfoInAuth []ExtInfoField

	// AuthMethods replaces the "authentications that can continue" list.
	AuthMethods []string

	// AuthPolicy models the server's failed-authentication behaviour. Nil
	// keeps this package's.
	AuthPolicy *AuthPolicy
}

// AuthPolicy is how a server treats failed USERAUTH_REQUESTs. With a policy
// set, a public key the server would refuse is refused without checking a
// signature that comes with it, as OpenSSH and dropbear do.
type AuthPolicy struct {
	// Failed runs for each failed request before its reply is sent and may
	// sleep to model the server's failure delay. It reports whether the
	// failure counts toward MaxAuthTries; query marks a public key query.
	// Nil counts every failure.
	Failed func(user, method string, query bool) bool

	// Disconnect is the SSH_MSG_DISCONNECT text (reason 2) sent in place of
	// the reply that reaches MaxAuthTries. Empty closes without a message.
	Disconnect string
}

// ExtInfoField is one RFC 8308 extension.
type ExtInfoField struct {
	Name, Value string
}

// Names advertised by OpenSSH servers that are not algorithms.
const (
	extInfoServer = "ext-info-s"
	// KeyExchangeDH18SHA512 is RFC 8268 group 18.
	KeyExchangeDH18SHA512 = "diffie-hellman-group18-sha512"
	// HMACSHA1ETM is OpenSSH's encrypt-then-MAC HMAC-SHA1.
	HMACSHA1ETM = "hmac-sha1-etm@openssh.com"
)

const oakleyGroup18 = "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFCE0FD108E4B82D120A92108011A723C12A787E6D788719A10BDBA5B2699C327186AF4E23C1A946834B6150BDA2583E9CA2AD44CE8DBBBC2DB04DE8EF92E8EFC141FBECAA6287C59474E6BC05D99B2964FA090C3A2233BA186515BE7ED1F612970CEE2D7AFB81BDD762170481CD0069127D5B05AA993B4EA988D8FDDC186FFB7DC90A6C08F4DF435C93402849236C3FAB4D27C7026C1D4DCB2602646DEC9751E763DBA37BDF8FF9406AD9E530EE5DB382F413001AEB06A53ED9027D831179727B0865A8918DA3EDBEBCF9B14ED44CE6CBACED4BB1BDB7F1447E6CC254B332051512BD7AF426FB8F401378CD2BF5983CA01C64B92ECF032EA15D1721D03F482D7CE6E74FEF6D55E702F46980C82B5A84031900B1C9E59E7C97FBEC7E8F323A97A7E36CC88BE0F1D45B7FF585AC54BD407B22B4154AACC8F6D7EBF48E1D814CC5ED20F8037E0A79715EEF29BE32806A1D58BB7C5DA76F550AA3D8A1FBFF0EB19CCB1A313D55CDA56C9EC2EF29632387FE8D76E3C0468043E8F663F4860EE12BF2D5B0B7474D6E694F91E6DBE115974A3926F12FEE5E438777CB6A932DF8CD8BEC4D073B931BA3BC832B68D9DD300741FA7BF8AFC47ED2576F6936BA424663AAB639C5AE4F5683423B4742BF1C978238F16CBE39D652DE3FDB8BEFC848AD922222E04A4037C0713EB57A81A23F0C73473FC646CEA306B4BCBC8862F8385DDFA9D4B7FA2C087E879683303ED5BDD3A062B3CF5B3A278A66D2A13F83F44F82DDF310EE074AB6A364597E899A0255DC164F31CC50846851DF9AB48195DED7EA1B1D510BD7EE74D73FAF36BC31ECFA268359046F4EB879F924009438B481C6CD7889A002ED5EE382BC9190DA6FC026E479558E4475677E9AA9E3050E2765694DFC81F56E880B96E7160C980DD98EDD3DFFFFFFFFFFFFFFFFF"

func init() {
	kexAlgoMap[KeyExchangeSNTRUP761X25519] = &sntrup761WithCurve25519sha512{}
	kexAlgoMap[KeyExchangeSNTRUP761X25519OpenSSH] = &sntrup761WithCurve25519sha512{}
	p, _ := new(big.Int).SetString(oakleyGroup18, 16)
	kexAlgoMap[KeyExchangeDH18SHA512] = &dhGroup{
		g:        new(big.Int).SetInt64(2),
		p:        p,
		pMinus1:  new(big.Int).Sub(p, bigOne),
		hashFunc: crypto.SHA512,
	}
	macModes[HMACSHA1ETM] = &macMode{20, true, func(key []byte) hash.Hash {
		return hmac.New(sha1.New, key)
	}}
}

// personalityKexInit fills msg from p for a server's KEXINIT. On a re-key the
// first-exchange markers are dropped, as OpenSSH does.
func personalityKexInit(p *Personality, msg *kexInitMsg, firstKex bool) {
	kex := slices.Clone(p.KeyExchanges)
	if !firstKex {
		kex = slices.DeleteFunc(kex, func(s string) bool { return s == extInfoServer || s == kexStrictServer })
	}
	msg.KexAlgos = kex
	msg.ServerHostKeyAlgos = slices.Clone(p.HostKeyAlgorithms)
	msg.CiphersClientServer = p.Ciphers
	msg.CiphersServerClient = p.Ciphers
	msg.MACsClientServer = p.MACs
	msg.MACsServerClient = p.MACs
	comp := p.Compressions
	if len(comp) == 0 {
		comp = supportedCompressions
	}
	msg.CompressionClientServer = comp
	msg.CompressionServerClient = comp
}

// marshalExtInfo builds an SSH_MSG_EXT_INFO from fields.
func marshalExtInfo(fields []ExtInfoField) []byte {
	m := &extInfoMsg{NumExtensions: uint32(len(fields))}
	for _, f := range fields {
		m.Payload = appendInt(m.Payload, len(f.Name))
		m.Payload = append(m.Payload, f.Name...)
		m.Payload = appendInt(m.Payload, len(f.Value))
		m.Payload = append(m.Payload, f.Value...)
	}
	return Marshal(m)
}

// clientWantsExtInfoInAuth reports whether a client EXT_INFO names
// ext-info-in-auth@openssh.com.
func clientWantsExtInfoInAuth(packet []byte) bool {
	var m extInfoMsg
	if err := Unmarshal(packet, &m); err != nil {
		return false
	}
	b := m.Payload
	for i := uint32(0); i < m.NumExtensions; i++ {
		name, rest, ok := parseString(b)
		if !ok {
			return false
		}
		if _, rest, ok = parseString(rest); !ok {
			return false
		}
		if string(name) == "ext-info-in-auth@openssh.com" {
			return true
		}
		b = rest
	}
	return false
}

// PersonalityAlgorithms lists the names a Personality may advertise that
// this package runs but does not offer by default.
func PersonalityAlgorithms() Algorithms {
	return Algorithms{
		KeyExchanges: []string{KeyExchangeSNTRUP761X25519, KeyExchangeSNTRUP761X25519OpenSSH, KeyExchangeDH18SHA512, "curve25519-sha256@libssh.org"},
		MACs:         []string{HMACSHA1ETM, UMAC64, UMAC128, UMAC64ETM, UMAC128ETM},
	}
}

// PersonalityCompressions lists the compression names this package runs.
func PersonalityCompressions() []string {
	return []string{compressionNone, compressionZlib, compressionDelayed}
}

// checkNegotiated rejects an agreement on an advertised name this package
// cannot run.
func checkNegotiated(a *NegotiatedAlgorithms) error {
	if kexAlgoMap[a.KeyExchange] == nil {
		return fmt.Errorf("ssh: negotiated key exchange %q is advertised but not implemented", a.KeyExchange)
	}
	for _, d := range []DirectionAlgorithms{a.Read, a.Write} {
		if cipherModes[d.Cipher] == nil {
			return fmt.Errorf("ssh: negotiated cipher %q is advertised but not implemented", d.Cipher)
		}
		if !aeadCiphers[d.Cipher] && macModes[d.MAC] == nil {
			return fmt.Errorf("ssh: negotiated MAC %q is advertised but not implemented", d.MAC)
		}
		if !slices.Contains(PersonalityCompressions(), d.compression) {
			return fmt.Errorf("ssh: negotiated compression %q is advertised but not implemented", d.compression)
		}
	}
	return nil
}
