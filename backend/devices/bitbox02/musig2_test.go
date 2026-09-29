// SPDX-License-Identifier: Apache-2.0

package bitbox02

import (
	"testing"

	keystorePkg "github.com/BitBoxSwiss/bitbox-wallet-app/backend/keystore"
	"github.com/BitBoxSwiss/bitbox02-api-go/api/firmware"
	"github.com/BitBoxSwiss/bitbox02-api-go/api/firmware/messages"
	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/stretchr/testify/require"
)

// TestMuSig2SessionsTwoRounds asserts that the session ID of a nonce round is
// kept for the signing round of the same transaction, and only once.
func TestMuSig2SessionsTwoRounds(t *testing.T) {
	var sessions muSig2Sessions
	txHash := chainhash.Hash{1}

	options, sign, stale, err := sessions.begin(
		firmware.PSBTMuSig2StepNonce, txHash,
	)
	require.NoError(t, err)
	require.True(t, sign)
	require.Nil(t, stale)
	require.Equal(t, messages.BTCMuSig2Init_NONCE, options.Phase)

	// The device assigns the session ID during the call.
	options.SessionID = []byte("session")
	sessions.complete(options, txHash)

	// Waiting for the other participants' nonces needs no device.
	_, sign, _, err = sessions.begin(firmware.PSBTMuSig2StepWait, txHash)
	require.NoError(t, err)
	require.False(t, sign)

	options, sign, _, err = sessions.begin(firmware.PSBTMuSig2StepSign, txHash)
	require.NoError(t, err)
	require.True(t, sign)
	require.Equal(t, messages.BTCMuSig2Init_SIGN, options.Phase)
	require.Equal(t, []byte("session"), options.SessionID)

	// The device consumed the round, even if the signing call fails.
	_, _, _, err = sessions.begin(firmware.PSBTMuSig2StepSign, txHash)
	require.ErrorIs(t, err, keystorePkg.ErrMuSig2SessionLost)
	sessions.complete(options, txHash)
	require.Nil(t, sessions.pending)

	_, sign, _, err = sessions.begin(firmware.PSBTMuSig2StepDone, txHash)
	require.NoError(t, err)
	require.False(t, sign)
}

// TestMuSig2SessionsLost asserts that a signing round is refused if the nonce
// round was for another transaction or is unknown.
func TestMuSig2SessionsLost(t *testing.T) {
	var sessions muSig2Sessions
	_, _, _, err := sessions.begin(firmware.PSBTMuSig2StepSign, chainhash.Hash{1})
	require.ErrorIs(t, err, keystorePkg.ErrMuSig2SessionLost)

	sessions.complete(&firmware.PSBTMuSig2Options{
		Phase:     messages.BTCMuSig2Init_NONCE,
		SessionID: []byte("session"),
	}, chainhash.Hash{1})
	_, _, _, err = sessions.begin(firmware.PSBTMuSig2StepSign, chainhash.Hash{2})
	require.ErrorIs(t, err, keystorePkg.ErrMuSig2SessionLost)
	require.Nil(t, sessions.pending)
}

// TestMuSig2SessionsReplaced asserts that a new nonce round abandons the
// pending one, and that reset forgets it.
func TestMuSig2SessionsReplaced(t *testing.T) {
	var sessions muSig2Sessions
	nonce := &firmware.PSBTMuSig2Options{
		Phase:     messages.BTCMuSig2Init_NONCE,
		SessionID: []byte("first"),
	}
	sessions.complete(nonce, chainhash.Hash{1})

	_, sign, stale, err := sessions.begin(
		firmware.PSBTMuSig2StepNonce, chainhash.Hash{2},
	)
	require.NoError(t, err)
	require.True(t, sign)
	require.Equal(t, []byte("first"), stale)
	require.Nil(t, sessions.pending)

	sessions.complete(nonce, chainhash.Hash{1})
	require.Equal(t, []byte("first"), sessions.reset())
	require.Nil(t, sessions.reset())
}

// TestMuSig2SessionsStateless asserts the steps that never involve a pending
// round.
func TestMuSig2SessionsStateless(t *testing.T) {
	var sessions muSig2Sessions

	options, sign, _, err := sessions.begin(
		firmware.PSBTMuSig2StepNone, chainhash.Hash{},
	)
	require.NoError(t, err)
	require.True(t, sign)
	require.Nil(t, options)

	options, sign, _, err = sessions.begin(
		firmware.PSBTMuSig2StepNonceAndSign, chainhash.Hash{},
	)
	require.NoError(t, err)
	require.True(t, sign)
	require.Equal(t, messages.BTCMuSig2Init_NONCE_AND_SIGN, options.Phase)
	sessions.complete(options, chainhash.Hash{})
	require.Nil(t, sessions.pending)

	_, _, _, err = sessions.begin(firmware.PSBTMuSig2Step(99), chainhash.Hash{})
	require.Error(t, err)
}

// TestMuSig2ResetWithoutPending asserts that a reset without a pending round
// does not talk to the device.
func TestMuSig2ResetWithoutPending(t *testing.T) {
	newKeystoreWithVersion(minMuSig2Version).MuSig2Reset()
}

// The BitBox02 keystore keeps MuSig2 state between signing calls.
var _ keystorePkg.MuSig2Resetter = (*keystore)(nil)
