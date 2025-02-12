package libssl

// CtxConfig is used to configure the SSLCtx
type CtxConfig struct {
	MinTLS     int64
	MaxTLS     int64
	Options    int64
	VerifyMode int
	NextProto  string
	CaFile     string
	CaPath     string
	CertFile   string
	KeyFile    string
}
