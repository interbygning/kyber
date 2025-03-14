package s256

import (
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

// P256 implements the kyber.Group interface
// for the NIST P-256 elliptic curve,
// based on Go's native elliptic curve library.
type s256 struct {
	curve
}

func (curve *s256) String() string {
	return "S256"
}

// Init initializes standard Curve instances
func (curve *s256) Init() curve {
	curve.curve.Curve = secp256k1.S256()
	curve.p = curve.Params()
	//curve.curveOps = curve
	return curve.curve
}
