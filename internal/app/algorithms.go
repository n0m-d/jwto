package app

import (
	"github.com/golang-jwt/jwt/v5"
)

// noneAlgorithm is a generic implementation for "none" algorithm variants
type noneAlgorithm struct {
	algName string
}

var (
	Algnone  = &noneAlgorithm{algName: "none"}
	AlgNone  = &noneAlgorithm{algName: "None"}
	AlgNONE  = &noneAlgorithm{algName: "NONE"}
	NoneAlgs = map[string]interface{}{
		"none": Algnone,
		"None": AlgNone,
		"NONE": AlgNONE,
	}
)

func init() {
	for _, alg := range []*noneAlgorithm{Algnone, AlgNone, AlgNONE} {
		jwt.RegisterSigningMethod(alg.Alg(), func(a *noneAlgorithm) func() jwt.SigningMethod {
			return func() jwt.SigningMethod { return a }
		}(alg))
	}
}

func (m *noneAlgorithm) Alg() string {
	return m.algName
}

func (m *noneAlgorithm) Verify(signingString string, sig []byte, key any) error {
	return nil
}

func (m *noneAlgorithm) Sign(signingString string, key any) ([]byte, error) {
	return nil, nil
}
