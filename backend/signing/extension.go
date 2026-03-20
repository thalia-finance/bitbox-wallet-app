// SPDX-License-Identifier: Apache-2.0

package signing

import "github.com/btcsuite/btcd/btcutil/hdkeychain"

// ConfigurationExtension is an optional plug-in carried by
// Configuration.Extension. It lets downstream consumers add new
// signing-configuration shapes (multisig, miniscript policies, …)
// without modifying signing.Configuration itself.
//
// When a Configuration's Extension field is non-nil, the standard
// helpers on Configuration (ScriptType, AbsoluteKeypath,
// ExtendedPublicKey, AccountNumber, String) delegate to the extension
// instead of the BitcoinSimple / EthereumSimple union members. The
// Configurations slice's RootFingerprint, ContainsRootFingerprint, and
// FindScriptType do the same. Fee estimation in maketx delegates via
// MaxSigAndWitnessSize.
//
// Implementations live downstream (e.g. in a thalia-app multisig
// package) and do not need to be registered anywhere: a Configuration
// with Extension set just behaves correctly.
type ConfigurationExtension interface {
	// ScriptType returns the configuration's script type. The value is
	// opaque to upstream code — it is only compared against itself
	// (via Configurations.FindScriptType) and used in logging.
	ScriptType() ScriptType

	// AbsoluteKeypath returns the configuration's account-level keypath.
	AbsoluteKeypath() AbsoluteKeypath

	// ExtendedPublicKey returns one of the extended public keys carried
	// by this configuration. Multi-key extensions (multisig) may return
	// any representative key — callers must not assume there is only
	// one. Used as the derivation root for child-key derivation in the
	// standard single-sig path; extensions that handle their own
	// derivation are free to return one of the cosigner xpubs and
	// ignore upstream derivation calls.
	ExtendedPublicKey() *hdkeychain.ExtendedKey

	// AccountNumber returns the BIP-44 account number embedded in the
	// keypath. Returns an error if the keypath does not fit a known
	// account-level layout.
	AccountNumber() (uint16, error)

	// RootFingerprint returns a representative root fingerprint for
	// this configuration. For multi-signer extensions this may be a
	// combined fingerprint (e.g. XOR) rather than a single signer's.
	RootFingerprint() []byte

	// ContainsRootFingerprint returns true if any signer in this
	// configuration matches the given root fingerprint.
	ContainsRootFingerprint(rootFingerprint []byte) bool

	// String returns a short summary of the extension for logging.
	String() string

	// MaxSigAndWitnessSize returns the maximum scriptSig + witness
	// sizes for an input spending from this configuration. Used by
	// maketx for fee estimation. Standard single-sig script types are
	// handled by maketx directly; configurations whose ScriptType
	// doesn't match a standard case must implement this.
	MaxSigAndWitnessSize() (sigScriptSize, witnessSize int, err error)
}
