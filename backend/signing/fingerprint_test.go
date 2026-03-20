package signing

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestFingerprintConversion(t *testing.T) {
	tests := []struct {
		name     string
		input    []byte
		expected uint32
	}{
		{
			name:     "zeros",
			input:    []byte{0x00, 0x00, 0x00, 0x00},
			expected: 0,
		},
		{
			name:     "ones",
			input:    []byte{0xff, 0xff, 0xff, 0xff},
			expected: 4294967295,
		},
		{
			name:     "little endian",
			input:    []byte{0x01, 0x02, 0x03, 0x04},
			expected: 0x04030201,
		},
		{
			name:     "mixed",
			input:    []byte{0x12, 0x34, 0x56, 0x78},
			expected: 0x78563412,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(
				t, tc.expected, FingerprintToInt(tc.input),
			)
			require.Equal(
				t, tc.input, FingerprintFromInt(tc.expected),
			)
		})
	}
}

func TestCombinedRootFingerprint(t *testing.T) {
	tests := []struct {
		name     string
		input    [][]byte
		expected []byte
	}{
		{
			name:     "empty",
			input:    [][]byte{},
			expected: nil,
		},
		{
			name: "single",
			input: [][]byte{
				{0x01, 0x02, 0x03, 0x04},
			},
			expected: []byte{0x01, 0x02, 0x03, 0x04},
		},
		{
			name: "two elements",
			input: [][]byte{
				{0x01, 0x02, 0x03, 0x04},
				{0x05, 0x06, 0x07, 0x08},
			},
			expected: []byte{0x04, 0x04, 0x04, 0x0c},
		},
		{
			name: "three elements",
			input: [][]byte{
				{0xff, 0xff, 0xff, 0xff},
				{0xaa, 0xaa, 0xaa, 0xaa},
				{0x33, 0x33, 0x33, 0x33},
			},
			expected: []byte{0x66, 0x66, 0x66, 0x66},
		},
		{
			name: "multiple with identical pairs",
			input: [][]byte{
				{0xaa, 0xaa, 0xaa, 0xaa},
				{0xaa, 0xaa, 0xaa, 0xaa},
			},
			expected: []byte{0x00, 0x00, 0x00, 0x00},
		},
		{
			name: "complex sequence",
			input: [][]byte{
				{0x12, 0x34, 0x56, 0x78},
				{0x9a, 0xbc, 0xde, 0xf0},
				{0x11, 0x22, 0x33, 0x44},
			},
			expected: []byte{
				0x12 ^ 0x9a ^ 0x11,
				0x34 ^ 0xbc ^ 0x22,
				0x56 ^ 0xde ^ 0x33,
				0x78 ^ 0xf0 ^ 0x44,
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(
				t, tc.expected,
				CombinedRootFingerprint(tc.input),
			)
		})
	}
}
