// SPDX-License-Identifier: Apache-2.0

package bitbox02

import (
	"github.com/BitBoxSwiss/bitbox02-api-go/api/firmware/messages"
)

// ScriptConfigProvider is optionally implemented by
// signing.ConfigurationExtension values whose script config the
// BitBox02 firmware cannot infer from the PSBT alone — multisig,
// miniscript policies, etc.
//
// The BitBox02 keystore queries every entry in
// btcProposedTransaction.AccountSigningConfigurations for this
// interface on its Extension and uses the first match's
// BB02ScriptConfig as the firmware's ForceScriptConfig. Standard
// single-sig configurations have no Extension and skip this check.
//
// signerFingerprint is the wallet's own root fingerprint, used by
// the implementer to fill in the firmware's `our_xpub_index`.
type ScriptConfigProvider interface {
	BB02ScriptConfig(signerFingerprint []byte) (
		*messages.BTCScriptConfigWithKeypath, error,
	)
}
