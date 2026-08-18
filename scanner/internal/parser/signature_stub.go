//go:build !windows

package parser

type SignatureInfo struct {
	Signed     bool     `json:"signed"`
	Verified   bool     `json:"verified"`
	Signer     string   `json:"signer"`
	Issuer     string   `json:"issuer"`
	Thumbprint string  `json:"thumbprint"`
	Chain      []string `json:"chain"`
}

func VerifySignature(filePath string) *SignatureInfo {
	return &SignatureInfo{
		Signed:   false,
		Verified: false,
	}
}
