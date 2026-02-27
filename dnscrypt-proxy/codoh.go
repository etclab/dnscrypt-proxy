package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/cloudflare/circl/hpke"
	"github.com/cloudflare/circl/kem"
	"github.com/jedisct1/dlog"
)

// HPKE suite: DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, AES-128-GCM
// Must match enclave/crypto.go and codoh-client/commands/blob.go.
var (
	hpkeKemID  = hpke.KEM_X25519_HKDF_SHA256
	hpkeKdfID  = hpke.KDF_HKDF_SHA256
	hpkeAeadID = hpke.AEAD_AES128GCM
	hpkeSuite  = hpke.NewSuite(hpkeKemID, hpkeKdfID, hpkeAeadID)
	hpkeInfo   = []byte("codoh transport key")
)

const (
	exportKeyLen             uint = 16
	codohResponseContentType      = "application/codoh-response"
	codohCachedContentType        = "application/codoh-cached"
)

var exportLabel = []byte("codoh response")

// Ensure kem package is used (for UnmarshalBinaryPublicKey)
var _ kem.PublicKey

// Tagged-chunk types — must match proxy's ChunkType* constants.
const (
	chunkTypeEnclave byte = 1 // Enclave blob (cache hit or dummy)
	chunkTypeTarget  byte = 2 // ODoH target response
)

// CODoHConfig holds per-server enclave state for the CODoH protocol.
type CODoHConfig struct {
	enclaveKeyURL string // https://<proxy>/enclave-keys
	proxyHost     string
	pubKey        []byte
	mu            sync.Mutex
}

// NewCODoHConfig creates a CODoHConfig for the given proxy host.
func NewCODoHConfig(proxyHost string) *CODoHConfig {
	return &CODoHConfig{
		proxyHost:     proxyHost,
		enclaveKeyURL: "https://" + proxyHost + "/enclave-keys",
	}
}

// GetOrFetchPubKey returns the cached enclave public key, fetching if needed.
func (c *CODoHConfig) GetOrFetchPubKey(xTransport *XTransport) ([]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if len(c.pubKey) > 0 {
		return c.pubKey, nil
	}
	return c.fetchLocked(xTransport)
}

// RefreshPubKey clears and re-fetches the enclave public key (key rotation).
func (c *CODoHConfig) RefreshPubKey(xTransport *XTransport) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	dlog.Info("Refreshing enclave public key (key rotation detected)")
	c.pubKey = nil
	_, err := c.fetchLocked(xTransport)
	return err
}

// fetchLocked fetches pk_E from /enclave-keys. Caller must hold c.mu.
func (c *CODoHConfig) fetchLocked(xTransport *XTransport) ([]byte, error) {
	u, err := url.Parse(c.enclaveKeyURL)
	if err != nil {
		return nil, fmt.Errorf("parse enclave key URL: %w", err)
	}

	body, statusCode, _, _, err := xTransport.Get(u, "", 10*time.Second)
	if err != nil {
		return nil, fmt.Errorf("fetch enclave key: %w", err)
	}
	if statusCode != http.StatusOK {
		return nil, fmt.Errorf("enclave key fetch failed (%d): %s", statusCode, string(body))
	}

	pk, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(body)))
	if err != nil {
		return nil, fmt.Errorf("decode enclave public key: %w", err)
	}

	c.pubKey = pk
	dlog.Debugf("Got enclave public key (%d bytes)", len(pk))
	return pk, nil
}

// EncryptQueryE encrypts a canonical query to the enclave's public key using HPKE.
// Returns Q_E ciphertext (enc || ct) and the session response key k_r.
// k_r = senderCtx.Export("codoh response", 16)
func EncryptQueryE(pkBytes []byte, query []byte) (qe []byte, kr []byte, err error) {
	pubKey, err := hpkeKemID.Scheme().UnmarshalBinaryPublicKey(pkBytes)
	if err != nil {
		return nil, nil, fmt.Errorf("unmarshal public key: %w", err)
	}

	sender, err := hpkeSuite.NewSender(pubKey, hpkeInfo)
	if err != nil {
		return nil, nil, fmt.Errorf("create sender: %w", err)
	}

	enc, sealer, err := sender.Setup(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("setup sender: %w", err)
	}

	ct, err := sealer.Seal(query, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("seal query: %w", err)
	}

	kr = sealer.Export(exportLabel, exportKeyLen)

	qe = make([]byte, len(enc)+len(ct))
	copy(qe, enc)
	copy(qe[len(enc):], ct)

	return qe, kr, nil
}

// DecryptCachedResponse decrypts an enclave's cached response under k_r.
// Format: nonce (12 bytes) || AES-128-GCM ciphertext
func DecryptCachedResponse(key, encrypted []byte) ([]byte, error) {
	if len(key) < 16 {
		return nil, errors.New("key too short")
	}

	block, err := aes.NewCipher(key[:16])
	if err != nil {
		return nil, fmt.Errorf("create cipher: %w", err)
	}

	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("create gcm: %w", err)
	}

	nonceSize := aead.NonceSize()
	if len(encrypted) < nonceSize+aead.Overhead() {
		return nil, errors.New("ciphertext too short")
	}

	nonce := encrypted[:nonceSize]
	ciphertext := encrypted[nonceSize:]

	plaintext, err := aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("decrypt: %w", err)
	}

	return plaintext, nil
}

// CanonicalizeQuery creates a canonical cache key from a DNS query.
// Format: "lowercased.fqdn.:TYPE_NUMBER"
func CanonicalizeQuery(domain string, qtype uint16) string {
	domain = strings.ToLower(domain)
	if !strings.HasSuffix(domain, ".") {
		domain = domain + "."
	}
	return fmt.Sprintf("%s:%d", domain, qtype)
}

// UnpadFromBucket extracts the original data from a padded message.
// Reads the 2-byte LE length prefix and returns the inner data.
func UnpadFromBucket(padded []byte) ([]byte, error) {
	if len(padded) < 2 {
		return nil, errors.New("padded data too short")
	}

	dataLen := int(binary.LittleEndian.Uint16(padded[:2]))
	if 2+dataLen > len(padded) {
		return nil, fmt.Errorf("invalid length prefix: %d exceeds padded size %d", dataLen, len(padded)-2)
	}

	return padded[2 : 2+dataLen], nil
}

// DefaultQueryPadBuckets is the padding bucket set for queries (Q_E and Q_T).
// A single 256-byte bucket makes all queries identical size on the wire.
// Empirically: max Q_E ≈ 193B, max Q_T ≈ 180B (top-10k Umbrella domains).
var DefaultQueryPadBuckets = []int{256}

// PadToBucket pads data to the next bucket boundary.
// Wire format: [2-byte LE length prefix][data][random padding]
// Total output length equals the smallest bucket >= len(data)+2.
// If data+2 exceeds the largest bucket, rounds up to the next multiple of the largest.
// Must match enclave.PadToBucket wire format.
func PadToBucket(data []byte, buckets []int) ([]byte, error) {
	if len(buckets) == 0 {
		return nil, errors.New("empty bucket list")
	}

	needed := len(data) + 2 // 2-byte length prefix
	if needed > 65535+2 {
		return nil, errors.New("data too large for 2-byte length prefix")
	}

	// Find the smallest bucket that fits (buckets must be ascending sorted).
	targetSize := 0
	for _, b := range buckets {
		if b >= needed {
			targetSize = b
			break
		}
	}

	// If no bucket fits, round up to next multiple of largest bucket.
	if targetSize == 0 {
		largest := buckets[len(buckets)-1]
		targetSize = ((needed + largest - 1) / largest) * largest
	}

	out := make([]byte, targetSize)
	binary.LittleEndian.PutUint16(out[:2], uint16(len(data)))
	copy(out[2:], data)

	// Fill remaining bytes with random padding.
	padStart := 2 + len(data)
	if padStart < targetSize {
		rand.Read(out[padStart:])
	}

	return out, nil
}

// CODoHResult holds the result of a CODoH query.
type CODoHResult struct {
	Response []byte // Decrypted DNS response
	CacheHit bool
}

// ParseCODoHResponse parses a CODoH response body based on content type.
// Handles:
//   - application/codoh-response: tagged chunks [1B type][2B BE len][data]...
//   - application/oblivious-dns-message: degraded ODoH (enclave down)
func ParseCODoHResponse(contentType string, body []byte, kr []byte, odohQuery *ODoHQuery) (*CODoHResult, error) {
	switch contentType {
	case codohResponseContentType:
		return parseCODoHTaggedChunks(body, kr, odohQuery)

	case codohCachedContentType:
		// CODoH-base proxy mode: direct AES-GCM encrypted cached response
		decrypted, err := DecryptCachedResponse(kr, body)
		if err != nil {
			return nil, fmt.Errorf("decrypt codoh-cached response: %w", err)
		}
		dlog.Debug("CODoH cache HIT — codoh-cached (proxy mode)")
		return &CODoHResult{Response: decrypted, CacheHit: true}, nil

	case "application/oblivious-dns-message":
		// Degraded mode: enclave was down, standard ODoH response
		response, err := odohQuery.decryptResponse(body)
		if err != nil {
			return nil, fmt.Errorf("decrypt degraded ODoH response: %w", err)
		}
		dlog.Debug("CODoH degraded — standard ODoH response (enclave unavailable)")
		return &CODoHResult{Response: response, CacheHit: false}, nil

	default:
		return nil, fmt.Errorf("unexpected content type: %s, body: %s", contentType, string(body))
	}
}

// parseCODoHTaggedChunks parses tagged chunks from a CODoH response body.
// Chunk format: [1B type][2B BE length][data]
func parseCODoHTaggedChunks(data []byte, kr []byte, odohQuery *ODoHQuery) (*CODoHResult, error) {
	offset := 0
	for offset+3 <= len(data) {
		chunkType := data[offset]
		chunkLen := int(binary.BigEndian.Uint16(data[offset+1 : offset+3]))
		offset += 3

		if offset+chunkLen > len(data) {
			return nil, fmt.Errorf("chunk data truncated (type=%d, len=%d, remaining=%d)", chunkType, chunkLen, len(data)-offset)
		}
		chunkData := data[offset : offset+chunkLen]
		offset += chunkLen

		switch chunkType {
		case chunkTypeEnclave:
			unpadded, unpadErr := UnpadFromBucket(chunkData)
			if unpadErr == nil {
				decrypted, decErr := DecryptCachedResponse(kr, unpadded)
				if decErr == nil {
					dlog.Debug("CODoH cache HIT — enclave chunk decrypted")
					return &CODoHResult{Response: decrypted, CacheHit: true}, nil
				}
			}
			// AEAD failed = dummy blob, continue to next chunk

		case chunkTypeTarget:
			response, err := odohQuery.decryptResponse(chunkData)
			if err == nil {
				dlog.Debug("CODoH cache MISS — target chunk decrypted")
				return &CODoHResult{Response: response, CacheHit: false}, nil
			}
			dlog.Warnf("CODoH target chunk decrypt failed: %v", err)

		default:
			dlog.Debugf("CODoH unknown chunk type %d, skipping", chunkType)
		}
	}
	return nil, errors.New("no valid chunk in codoh-response")
}
