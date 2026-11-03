// SPDX-License-Identifier: Apache-2.0

package maketx

import (
	"testing"

	"github.com/BitBoxSwiss/bitbox-wallet-app/util/logging"
	"github.com/btcsuite/btcd/btcutil/v2"
	"github.com/stretchr/testify/require"
)

func TestFeeForSerializeSize(t *testing.T) {
	log := logging.Get().WithGroup("maketx_test")

	tests := []struct {
		name          string
		relayFeePerKb btcutil.Amount
		size          int
		expectedFee   btcutil.Amount
	}{
		{
			name:          "sub-sat rate rounds up",
			relayFeePerKb: 100,
			size:          154,
			expectedFee:   16,
		},
		{
			name:          "sub-sat rate on a multiple of 10 vbytes",
			relayFeePerKb: 100,
			size:          150,
			expectedFee:   15,
		},
		{
			name:          "whole sat/vB rate",
			relayFeePerKb: 1000,
			size:          154,
			expectedFee:   154,
		},
		{
			name:          "fractional rate rounds up",
			relayFeePerKb: 1500,
			size:          101,
			expectedFee:   152,
		},
		{
			name:          "zero size pays the per-kB rate",
			relayFeePerKb: 100,
			size:          0,
			expectedFee:   100,
		},
		{
			name:          "zero rate pays nothing",
			relayFeePerKb: 0,
			size:          154,
			expectedFee:   0,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			fee := feeForSerializeSize(tc.relayFeePerKb, tc.size, log)
			require.Equal(t, tc.expectedFee, fee)
		})
	}
}
