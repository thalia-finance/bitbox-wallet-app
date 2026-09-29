// SPDX-License-Identifier: Apache-2.0

package bitbox02

import (
	"sync"

	keystorePkg "github.com/BitBoxSwiss/bitbox-wallet-app/backend/keystore"
	"github.com/BitBoxSwiss/bitbox-wallet-app/util/errp"
	"github.com/BitBoxSwiss/bitbox02-api-go/api/firmware"
	"github.com/BitBoxSwiss/bitbox02-api-go/api/firmware/messages"
	"github.com/btcsuite/btcd/chainhash/v2"
)

// muSig2Sessions tracks the MuSig2 nonce round the device has pending. The
// firmware keeps at most one, so there is at most one here too.
type muSig2Sessions struct {
	mu sync.Mutex

	// pending is the pending nonce round, or nil.
	pending *muSig2Pending
}

// muSig2Pending is a nonce round the device keeps secret nonces for.
type muSig2Pending struct {
	// txHash is the hash of the unsigned transaction the nonces are for.
	txHash chainhash.Hash

	// sessionID is the device's handle for the round.
	sessionID []byte
}

// begin returns the MuSig2 options of the next signing call for a
// transaction in the given step, or nil for a transaction without MuSig2
// inputs. It returns false if the device has nothing to contribute right now.
//
// A pending nonce round that has to be abandoned for a new one is returned as
// stale, so the caller can tell the device.
func (s *muSig2Sessions) begin(step firmware.PSBTMuSig2Step,
	txHash chainhash.Hash) (options *firmware.PSBTMuSig2Options,
	sign bool, stale []byte, err error) {

	s.mu.Lock()
	defer s.mu.Unlock()

	switch step {
	case firmware.PSBTMuSig2StepNone:
		return nil, true, nil, nil

	case firmware.PSBTMuSig2StepWait, firmware.PSBTMuSig2StepDone:
		return nil, false, nil, nil

	case firmware.PSBTMuSig2StepNonce:
		// The device refuses a new round while one is pending.
		if s.pending != nil {
			stale = s.pending.sessionID
			s.pending = nil
		}
		return &firmware.PSBTMuSig2Options{
			Phase: messages.BTCMuSig2Init_NONCE,
		}, true, stale, nil

	case firmware.PSBTMuSig2StepSign:
		// The device consumes the pending round whatever the outcome
		// of the signing call, so it is forgotten here already.
		pending := s.pending
		s.pending = nil
		if pending == nil || pending.txHash != txHash {
			return nil, false, nil, errp.WithStack(
				keystorePkg.ErrMuSig2SessionLost,
			)
		}
		return &firmware.PSBTMuSig2Options{
			Phase:     messages.BTCMuSig2Init_SIGN,
			SessionID: pending.sessionID,
		}, true, nil, nil

	case firmware.PSBTMuSig2StepNonceAndSign:
		return &firmware.PSBTMuSig2Options{
			Phase: messages.BTCMuSig2Init_NONCE_AND_SIGN,
		}, true, nil, nil

	default:
		return nil, false, nil, errp.Newf("unknown MuSig2 step %d", step)
	}
}

// complete remembers the nonce round the device keeps pending after a
// successful signing call with the given options.
func (s *muSig2Sessions) complete(options *firmware.PSBTMuSig2Options,
	txHash chainhash.Hash) {

	if options == nil || options.Phase != messages.BTCMuSig2Init_NONCE {
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	s.pending = &muSig2Pending{
		txHash:    txHash,
		sessionID: options.SessionID,
	}
}

// reset forgets the pending nonce round and returns its session ID, or nil.
func (s *muSig2Sessions) reset() []byte {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.pending == nil {
		return nil
	}
	sessionID := s.pending.sessionID
	s.pending = nil

	return sessionID
}

// abortMuSig2 tells the device to destroy the secret nonces of a nonce round.
// Failing to do so is not fatal: the device drops the round on the next
// connection anyway, and it can never be used to sign again from here.
func (keystore *keystore) abortMuSig2(sessionID []byte) {
	if sessionID == nil {
		return
	}
	if err := keystore.device.BTCMuSig2Abort(sessionID); err != nil {
		keystore.log.WithError(err).Warn("Could not abort MuSig2 session")
	}
}

// MuSig2Reset implements keystore.MuSig2Resetter.
func (keystore *keystore) MuSig2Reset() {
	keystore.abortMuSig2(keystore.muSig2.reset())
}
