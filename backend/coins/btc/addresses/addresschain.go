// SPDX-License-Identifier: Apache-2.0

package addresses

import (
	"github.com/BitBoxSwiss/bitbox-wallet-app/backend/coins/btc/types"
	"github.com/BitBoxSwiss/bitbox-wallet-app/backend/signing"
	"github.com/BitBoxSwiss/bitbox-wallet-app/util/errp"
	"github.com/BitBoxSwiss/bitbox-wallet-app/util/locker"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/sirupsen/logrus"
)

// AddressFactory builds an AccountAddress for a given (configuration,
// derivation) pair. AddressChain calls it once per new address.
//
// Resolution order at chain-add time:
//
//  1. An explicit factory passed to NewAddressChain. Test code uses
//     this to inject mock address types.
//  2. The signing.Configuration's Extension, if it implements
//     AddressFactoryProvider. Downstream account types (multisig,
//     miniscript) wire themselves in this way without needing the
//     caller to know what factory to pass.
//  3. NewAccountAddress, which handles the standard single-sig
//     script types.
type AddressFactory func(
	accountConfiguration *signing.Configuration,
	derivation types.Derivation,
	net *chaincfg.Params,
	log *logrus.Entry,
) AccountAddress

// AddressFactoryProvider is optionally implemented by
// signing.ConfigurationExtension values whose addresses are not
// produced by NewAccountAddress (multisig, miniscript, …). The
// AddressChain probes Configuration.Extension for this interface
// when no explicit factory was supplied.
type AddressFactoryProvider interface {
	AddressFactory() AddressFactory
}

// AddressChain manages a chain of addresses derived from a configuration.
type AddressChain struct {
	accountConfiguration *signing.Configuration
	net                  *chaincfg.Params
	gapLimit             int
	change               bool
	addresses            []AccountAddress
	addressesByID        map[AddressID]AccountAddress
	addressesLock        locker.Locker
	isAddressUsed        func(AccountAddress) (bool, error)
	addressFactory       AddressFactory
	log                  *logrus.Entry
}

// NewAddressChain creates an address chain starting at m/<chainIndex> from the given configuration.
// addressFactory is optional — see AddressFactory for resolution order.
// Most callers pass nil; downstream account types either implement
// AddressFactoryProvider on their Extension or pass a factory here.
func NewAddressChain(
	accountConfiguration *signing.Configuration,
	net *chaincfg.Params,
	gapLimit int,
	change bool,
	isAddressUsed func(AccountAddress) (bool, error),
	log *logrus.Entry,
	addressFactory AddressFactory,
) *AddressChain {
	return &AddressChain{
		accountConfiguration: accountConfiguration,
		net:                  net,
		gapLimit:             gapLimit,
		change:               change,
		addresses:            []AccountAddress{},
		addressesByID:        map[AddressID]AccountAddress{},
		isAddressUsed:        isAddressUsed,
		addressFactory:       addressFactory,
		log: log.WithFields(logrus.Fields{"group": "addresses", "net": net.Name,
			"gap-limit": gapLimit, "change": change,
			"configuration": accountConfiguration.String()}),
	}
}

// GetUnused returns the last `gapLimit` unused addresses. EnsureAddresses() must be called
// beforehand.
func (addresses *AddressChain) GetUnused() ([]AccountAddress, error) {
	defer addresses.addressesLock.RLock()()
	unusedTailCount, err := addresses.unusedTailCount()
	if err != nil {
		return nil, err
	}
	if unusedTailCount < addresses.gapLimit {
		return nil, errp.New("concurrency error: Addresses not synced correctly")
	}
	return addresses.addresses[len(addresses.addresses)-unusedTailCount:], nil
}

// addAddress appends a new address at the end of the chain.
func (addresses *AddressChain) addAddress() AccountAddress {
	addresses.log.Debug("Add new address to chain")
	index := uint32(len(addresses.addresses))
	factory := addresses.resolveFactory()
	address := factory(
		addresses.accountConfiguration,
		types.Derivation{Change: addresses.change, AddressIndex: index},
		addresses.net,
		addresses.log,
	)
	addresses.addresses = append(addresses.addresses, address)
	addresses.addressesByID[address.PubkeyScriptHashHex()] = address
	return address
}

// resolveFactory picks the AddressFactory to use for this chain's
// configuration. See the AddressFactory doc comment for the resolution
// order (explicit param > Extension > NewAccountAddress default).
func (addresses *AddressChain) resolveFactory() AddressFactory {
	if addresses.addressFactory != nil {
		return addresses.addressFactory
	}
	if ext := addresses.accountConfiguration.Extension; ext != nil {
		if provider, ok := ext.(AddressFactoryProvider); ok {
			return provider.AddressFactory()
		}
	}
	return NewAccountAddress
}

// unusedTailCount returns the number of unused addresses at the end of the chain.
func (addresses *AddressChain) unusedTailCount() (int, error) {
	count := 0
	for i := len(addresses.addresses) - 1; i >= 0; i-- {
		used, err := addresses.isAddressUsed(addresses.addresses[i])
		if err != nil {
			return 0, err
		}
		if used {
			break
		}
		count++
	}
	addresses.log.WithField("tail-count", count).Debug("Unused tail count")
	return count, nil
}

// LookupByAddressID returns the address which matches the provided address ID. Returns nil
// if not found.
func (addresses *AddressChain) LookupByAddressID(addressID AddressID) AccountAddress {
	defer addresses.addressesLock.RLock()()
	return addresses.addressesByID[addressID]
}

// EnsureAddresses appends addresses to the address chain until there are `gapLimit` unused
// ones, and returns the new addresses.
//
// We deliberately do NOT hold `addressesLock` across the
// `unusedTailCount` call: it invokes `isAddressUsed` which calls
// into the embedder's DB layer, and the upstream
// `Transactions.Transactions(IsChange)` path opens a DB read tx and
// then takes `addressesLock.RLock` from inside its callback. Holding
// the writer lock across the DB call therefore creates an AB-BA
// cycle: addressesLock(W) waiting on DB ↔ DB tx waiting on
// addressesLock(R). We instead read the unused count under the read
// lock, then re-acquire the write lock to mutate. The chain only
// grows, so an outdated `unusedAddressCount` results in adding
// strictly more addresses than required — never fewer — which is
// safe (and converges on the next caller's iteration).
func (addresses *AddressChain) EnsureAddresses() ([]AccountAddress, error) {
	var unusedAddressCount int
	var err error
	func() {
		defer addresses.addressesLock.RLock()()
		unusedAddressCount, err = addresses.unusedTailCount()
	}()
	if err != nil {
		return nil, err
	}

	defer addresses.addressesLock.Lock()()
	addedAddresses := []AccountAddress{}
	for i := 0; i < addresses.gapLimit-unusedAddressCount; i++ {
		addedAddresses = append(addedAddresses, addresses.addAddress())
	}
	return addedAddresses, nil
}
