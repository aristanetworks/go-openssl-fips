package conn

type Config struct {
    // CaFile is the path to a file of CA certificates in PEM format.
	CaFile string

    // CaPath is the path to a directory containing CA certificates in PEM format. The files each
	// contain one CA certificate.
	CaPath string

    // InsecureSkipVerify controls whether a client verifies the server's
	// certificate chain and host name. If InsecureSkipVerify is true, crypto/tls
	// accepts any certificate presented by the server and any host name in that
	// certificate. In this mode, TLS is susceptible to machine-in-the-middle
	// attacks unless custom verification is used. This should be used only for
	// testing or in combination with VerifyConnection or VerifyPeerCertificate.
	InsecureSkipVerify bool

    // // CipherSuites is a list of enabled TLS 1.0–1.2 cipher suites. The order of
	// // the list is ignored. Note that TLS 1.3 ciphersuites are not configurable.
	// //
	// // If CipherSuites is nil, a safe default list is used. The default cipher
	// // suites might change over time. In Go 1.22 RSA key exchange based cipher
	// // suites were removed from the default list, but can be re-added with the
	// // GODEBUG setting tlsrsakex=1. In Go 1.23 3DES cipher suites were removed
	// // from the default list, but can be re-added with the GODEBUG setting
	// // tls3des=1.
	// CipherSuites []uint16

    // // MinVersion contains the minimum TLS version that is acceptable.
	// //
	// // By default, TLS 1.2 is currently used as the minimum. TLS 1.0 is the
	// // minimum supported by this package.
	// //
	// // The server-side default can be reverted to TLS 1.0 by including the value
	// // "tls10server=1" in the GODEBUG environment variable.
	// MinVersion uint16

	// // MaxVersion contains the maximum TLS version that is acceptable.
	// //
	// // By default, the maximum version supported by this package is used,
	// // which is currently TLS 1.3.
	// MaxVersion uint16
}