package libssl

// CtxConfig is used to configure the SSLCtx
type CtxConfig struct {
	MinTLS     uint16
	MaxTLS     uint16
	Options    int64
	VerifyMode int
	NextProto  string
	CaFile     string
	CaPath     string
	CertFile   string
	KeyFile    string
}
