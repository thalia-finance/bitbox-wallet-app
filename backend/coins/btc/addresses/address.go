// SPDX-License-Identifier: Apache-2.0

package addresses

import (
	"fmt"

	"github.com/BitBoxSwiss/bitbox-wallet-app/backend/coins/btc/blockchain"
	"github.com/BitBoxSwiss/bitbox-wallet-app/backend/coins/btc/types"
	ourbtcutil "github.com/BitBoxSwiss/bitbox-wallet-app/backend/coins/btc/util"
	"github.com/BitBoxSwiss/bitbox-wallet-app/backend/signing"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/txscript"
	"github.com/sirupsen/logrus"
)

// AddressID identifies a BTC/LTC address at the account/frontend boundary.
// It is permanently identical to the address scriptHashHex.
type AddressID = blockchain.ScriptHashHex

// NewAddressID creates an address ID from a pubkey script.
func NewAddressID(pubkeyScript []byte) AddressID {
	return blockchain.NewScriptHashHex(pubkeyScript)
}

// AccountAddress models an address that belongs to an account of the user.
type AccountAddress interface {
	ID() string
	String() string
	EncodeForHumans() string
	AccountConfiguration() *signing.Configuration
	Address() btcutil.Address
	Derivation() types.Derivation
	AbsoluteKeypath() signing.AbsoluteKeypath
	PublicKey() *btcec.PublicKey
	RedeemScript() []byte
	PubkeyScript() []byte
	PubkeyScriptHashHex() blockchain.ScriptHashHex
	ScriptForHashToSign() (bool, []byte)
}

// accountAddress models an address that belongs to an account of the user.
// It contains all the information needed to receive and spend funds.
type accountAddress struct {
	nativeAddress btcutil.Address

	// accountConfiguration is the account level configuration from which this address was derived.
	accountConfiguration *signing.Configuration

	// publicKey is the public key of a single-sig address.
	publicKey *btcec.PublicKey

	derivation types.Derivation

	// redeemScript stores the redeem script of a BIP16 P2SH output or nil if address type is not
	// P2SH.
	redeemScript []byte

	log *logrus.Entry
}

// NewAccountAddress creates a new account address.
func NewAccountAddress(
	accountConfiguration *signing.Configuration,
	derivation types.Derivation,
	net *chaincfg.Params,
	log *logrus.Entry,
) AccountAddress {

	log = log.WithFields(logrus.Fields{
		"accountConfiguration": accountConfiguration.String(),
		"change":               derivation.Change,
		"addressIndex":         derivation.AddressIndex,
	})
	log.Debug("Creating new account address")

	var address btcutil.Address
	var redeemScript []byte
	relativeKeypath := signing.NewEmptyRelativeKeypath().
		Child(derivation.SimpleChainIndex(), signing.NonHardened).
		Child(derivation.AddressIndex, signing.NonHardened)
	derivedXpub, err := relativeKeypath.Derive(accountConfiguration.ExtendedPublicKey())
	if err != nil {
		log.WithError(err).Panic("Failed to derive xpub.")
	}
	publicKey, err := derivedXpub.ECPubKey()
	if err != nil {
		log.WithError(err).Panic("Failed to convert an extended public key to a normal public key.")
	}

	publicKeyHash := btcutil.Hash160(publicKey.SerializeCompressed())
	switch accountConfiguration.ScriptType() {
	case signing.ScriptTypeP2PKH:
		address, err = btcutil.NewAddressPubKeyHash(publicKeyHash, net)
		if err != nil {
			log.WithError(err).Panic("Failed to get P2PKH addr. from public key hash.")
		}
	case signing.ScriptTypeP2WPKHP2SH:
		var segwitAddress *btcutil.AddressWitnessPubKeyHash
		segwitAddress, err = btcutil.NewAddressWitnessPubKeyHash(publicKeyHash, net)
		if err != nil {
			log.WithError(err).Panic("Failed to get p2wpkh-p2sh addr. from publ. key hash.")
		}
		redeemScript, err = txscript.PayToAddrScript(segwitAddress)
		if err != nil {
			log.WithError(err).Panic("Failed to get redeem script for segwit address.")
		}
		address, err = btcutil.NewAddressScriptHash(redeemScript, net)
		if err != nil {
			log.WithError(err).Panic("Failed to get a P2SH address for segwit.")
		}
	case signing.ScriptTypeP2WPKH:
		address, err = btcutil.NewAddressWitnessPubKeyHash(publicKeyHash, net)
		if err != nil {
			log.WithError(err).Panic("Failed to get p2wpkh addr. from publ. key hash.")
		}
	case signing.ScriptTypeP2TR:
		outputKey := txscript.ComputeTaprootKeyNoScript(publicKey)
		address, err = btcutil.NewAddressTaproot(schnorr.SerializePubKey(outputKey), net)
		if err != nil {
			log.WithError(err).Panic("Failed to get p2tr addr")
		}
	default:
		log.Panic(fmt.Sprintf("Unrecognized script type: %s", accountConfiguration.ScriptType()))
	}

	return &accountAddress{
		nativeAddress:        address,
		accountConfiguration: accountConfiguration,
		publicKey:            publicKey,
		derivation:           derivation,
		redeemScript:         redeemScript,
		log:                  log,
	}
}

// ID implements accounts.Address.
// For BTC/LTC, this value must never change because it is treated interchangeably with the
// address scriptHashHex.
func (address *accountAddress) ID() string {
	return string(address.PubkeyScriptHashHex())
}

// String returns a representation of the address for logging.
func (address *accountAddress) String() string {
	return address.EncodeForHumans()
}

// EncodeForHumans implements accounts.Address.
func (address *accountAddress) EncodeForHumans() string {
	return address.nativeAddress.EncodeAddress()
}

// AccountConfiguration returns the account's configuration.
func (address *accountAddress) AccountConfiguration() *signing.Configuration {
	return address.accountConfiguration
}

// Address returns the underlying native address.
func (address *accountAddress) Address() btcutil.Address {
	return address.nativeAddress
}

// Derivation returns the derivation information of this address.
func (address *accountAddress) Derivation() types.Derivation {
	return address.derivation
}

// AbsoluteKeypath implements accounts.Address.
func (address *accountAddress) AbsoluteKeypath() signing.AbsoluteKeypath {
	return address.accountConfiguration.AbsoluteKeypath().
		Child(address.derivation.SimpleChainIndex(), false).
		Child(address.derivation.AddressIndex, false)
}

// PublicKey returns the public key of this address.
func (address *accountAddress) PublicKey() *btcec.PublicKey {
	return address.publicKey
}

// RedeemScript returns the redeem script of this address.
func (address *accountAddress) RedeemScript() []byte {
	return address.redeemScript
}

// PubkeyScript returns the pubkey script of this address. Use this in a tx output to receive funds.
func (address *accountAddress) PubkeyScript() []byte {
	script, err := ourbtcutil.PkScriptFromAddress(address.nativeAddress)
	if err != nil {
		address.log.WithError(err).Panic("Failed to get the pubkey script for an address.")
	}
	return script
}

// PubkeyScriptHashHex returns the hash of the pubkey script in hex format.
// It is used to subscribe to notifications at the ElectrumX server.
func (address *accountAddress) PubkeyScriptHashHex() blockchain.ScriptHashHex {
	return blockchain.NewScriptHashHex(address.PubkeyScript())
}

// ScriptForHashToSign returns whether this address is a segwit output and the script used when
// calculating the hash to be signed in a transaction. This info is needed when trying to spend
// from this address.
func (address *accountAddress) ScriptForHashToSign() (bool, []byte) {
	switch address.accountConfiguration.ScriptType() {
	case signing.ScriptTypeP2PKH:
		return false, address.PubkeyScript()
	case signing.ScriptTypeP2WPKHP2SH:
		return true, address.redeemScript
	case signing.ScriptTypeP2WPKH:
		return true, address.PubkeyScript()
	default:
		address.log.Panic("Unrecognized address type.")
	}
	panic("The end of the function cannot be reached.")
}
