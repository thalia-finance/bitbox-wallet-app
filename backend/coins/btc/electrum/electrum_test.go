// SPDX-License-Identifier: Apache-2.0

package electrum

import (
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/BitBoxSwiss/bitbox-wallet-app/backend/config"
	"github.com/BitBoxSwiss/bitbox-wallet-app/util/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDownloadCert(t *testing.T) {
	tt := []struct{ targetServer, wantServerName string }{
		{"node.example.org:123", "node.example.org"},
		{"1.2.3.4:123", ""},
	}
	for _, testcase := range tt {
		t.Run(testcase.targetServer, func(t *testing.T) {
			// Set up a fake ElectrumX node.
			var didHandshake bool
			fakeNode := &test.TCPServer{
				GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
					didHandshake = true
					assert.Equal(t, testcase.wantServerName, hello.ServerName, "hello.ServerName")
					return test.TCPServerCert, nil
				},
			}
			fakeNode.StartTLS(func(conn net.Conn) {
				conn.Write([]byte("ok")) // unused; just to finish TLS handshake
				conn.Close()
			})
			defer fakeNode.Close()

			// Make sure the client always connects directly to the fake node.
			dialer := &test.Dialer{DialFn: func(network, addr string) (net.Conn, error) {
				assert.Equal(t, testcase.targetServer, addr, "dialer addr")
				return fakeNode.Dialer().Dial(network, addr)
			}}

			// Run the test.
			done := make(chan struct{})
			go func() {
				cert, err := DownloadCert(testcase.targetServer, dialer)
				require.NoError(t, err, "DownloadCert")
				expected, actual := strings.TrimSpace(test.TCPServerCertPub), strings.TrimSpace(cert)
				assert.Equal(t, expected, actual, "DownloadCert")
				assert.True(t, didHandshake, "didHandshake")
				close(done)
			}()

			select {
			case <-time.After(3 * time.Second):
				t.Fatal("DownloadCert took too long to return")
			case <-done:
				// ok
			}
		})
	}
}

func TestEstablishConnectionTLS(t *testing.T) {
	tt := []struct{ targetServer, wantServerName string }{
		{"node.example.org:123", "node.example.org"},
		{"1.2.3.4:123", ""},
	}
	for _, testcase := range tt {
		t.Run(testcase.targetServer, func(t *testing.T) {
			// Set up a fake ElectrumX node.
			var didHandshake bool
			fakeNode := &test.TCPServer{
				GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
					didHandshake = true
					assert.Equal(t, testcase.wantServerName, hello.ServerName, "hello.ServerName")
					return test.TCPServerCert, nil
				},
			}
			fakeNode.StartTLS(func(conn net.Conn) {
				io.Copy(conn, conn) // echo back all incoming data
				conn.Close()
			})
			defer fakeNode.Close()

			// Make sure the client always connects directly to the fake node.
			dialer := &test.Dialer{DialFn: func(network, addr string) (net.Conn, error) {
				assert.Equal(t, testcase.targetServer, addr, "dialer addr")
				return fakeNode.Dialer().Dial(network, addr)
			}}

			// Run the test.
			info := &config.ServerInfo{
				Server:  testcase.targetServer,
				TLS:     true,
				PEMCert: test.TCPServerCertPub,
			}
			done := make(chan struct{})
			go func() {
				conn, err := establishConnection(info, dialer)
				require.NoError(t, err, "establishConnection")
				conn.Write([]byte("hello"))
				var buf = make([]byte, 5)
				conn.Read(buf)
				assert.Equal(t, "hello", string(buf), "conn.Read")
				conn.Close()
				assert.True(t, didHandshake, "didHandshake")
				close(done)
			}()

			select {
			case <-time.After(3 * time.Second):
				t.Fatal("establishConnection took too long to return")
			case <-done:
				// ok
			}
		})
	}
}

// TestEstablishConnectionTLSSystemRoots covers servers configured without a pinned certificate:
// the chain must verify against the system roots and the certificate must match the server's
// hostname, both of which the pinned path skips.
func TestEstablishConnectionTLSSystemRoots(t *testing.T) {
	trusted := x509.NewCertPool()
	require.True(t, trusted.AppendCertsFromPEM([]byte(test.TCPServerCertPub)))

	tt := []struct {
		name         string
		targetServer string
		roots        *x509.CertPool
		wantErr      bool
	}{
		{
			name:         "trusted cert for the hostname",
			targetServer: "node.example.org:123",
			roots:        trusted,
		},
		{
			name:         "trusted cert for another hostname",
			targetServer: "other.example.org:123",
			roots:        trusted,
			wantErr:      true,
		},
		{
			// The cert has no IP SAN, so an IP address can't match it.
			name:         "trusted cert without the IP address",
			targetServer: "1.2.3.4:123",
			roots:        trusted,
			wantErr:      true,
		},
		{
			name:         "untrusted cert",
			targetServer: "node.example.org:123",
			roots:        x509.NewCertPool(),
			wantErr:      true,
		},
	}
	for _, testcase := range tt {
		t.Run(testcase.name, func(t *testing.T) {
			defer func(orig *x509.CertPool) { systemRootCAs = orig }(systemRootCAs)
			systemRootCAs = testcase.roots

			fakeNode := &test.TCPServer{}
			fakeNode.StartTLS(func(conn net.Conn) {
				io.Copy(conn, conn) // echo back all incoming data
				conn.Close()
			})
			defer fakeNode.Close()

			dialer := &test.Dialer{DialFn: func(network, addr string) (net.Conn, error) {
				return fakeNode.Dialer().Dial(network, addr)
			}}

			info := &config.ServerInfo{
				Server: testcase.targetServer,
				TLS:    true,
			}
			conn, err := establishConnection(info, dialer)
			require.NoError(t, err, "establishConnection")
			defer conn.Close()

			// The handshake, and with it the verification, runs lazily on first use.
			_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
			err = conn.(*tls.Conn).Handshake()
			if testcase.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)

			_, err = conn.Write([]byte("hello"))
			require.NoError(t, err)
			buf := make([]byte, 5)
			_, err = io.ReadFull(conn, buf)
			require.NoError(t, err)
			require.Equal(t, "hello", string(buf))
		})
	}
}
