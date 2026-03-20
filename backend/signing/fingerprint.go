package signing

import (
	"encoding/binary"
	"fmt"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/btcutil/hdkeychain"
)

// RootFingerprint returns the root fingerprint of the given root key. The root
// fingerprint is the first 4 bytes of the hash160 of the pubkey at the keypath
// m/. The given extended key must be at depth 0.
func RootFingerprint(rootKey *hdkeychain.ExtendedKey) ([]byte, error) {
	if rootKey.Depth() != 0 {
		return nil, fmt.Errorf("root key must have depth 0")
	}

	pubKey, err := rootKey.ECPubKey()
	if err != nil {
		return nil, fmt.Errorf("failed to get public key from root "+
			"key: %w", err)
	}

	rootFingerprint := btcutil.Hash160(pubKey.SerializeCompressed())[:4]
	return rootFingerprint, nil
}

// FingerprintToInt converts a 4-byte fingerprint to a uint32.
func FingerprintToInt(fp []byte) uint32 {
	return binary.LittleEndian.Uint32(fp)
}

// FingerprintFromInt converts a uint32 to a 4-byte fingerprint.
func FingerprintFromInt(fp uint32) []byte {
	var fpBytes [4]byte
	binary.LittleEndian.PutUint32(fpBytes[:], fp)
	return fpBytes[:]
}

// CombinedRootFingerprint returns the combined root fingerprint of the given
// fingerprints by XORing them when interpreted as uint32.
func CombinedRootFingerprint(fingerprints [][]byte) []byte {
	switch len(fingerprints) {
	case 0:
		return nil

	case 1:
		return fingerprints[0]

	default:
		combined := FingerprintToInt(fingerprints[0])
		for _, fp := range fingerprints[1:] {
			combined ^= FingerprintToInt(fp)
		}
		return FingerprintFromInt(combined)
	}
}
