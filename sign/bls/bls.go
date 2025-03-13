// Package bls implements the Boneh-Lynn-Shacham (BLS) signature scheme which
// was introduced in the paper "Short Signatures from the Weil Pairing". BLS
// requires pairing-based cryptography.
//
// When using aggregated signatures, this version is vulnerable to rogue
// public-key attack.
// The `sign/bdn` package should be used to make sure a signature
// aggregate cannot be verified by a forged key. You can find the protocol
// in kyber/sign/bdn. Note that only the aggregation is broken against the
// attack and for that reason, the code performing aggregation was removed.
//
// See the paper: https://crypto.stanford.edu/~dabo/pubs/papers/BLSmultisig.html
package bls

import (
	"crypto/cipher"
	"errors"
	"fmt"
	"math/big"

	"go.dedis.ch/kyber/v4"
	"go.dedis.ch/kyber/v4/group/mod"
	"go.dedis.ch/kyber/v4/pairing"
	"go.dedis.ch/kyber/v4/sign"
)

type Scheme struct {
	sigGroup kyber.Group
	keyGroup kyber.Group
	pairing  func(signature, public, hashedPoint kyber.Point) bool
}

// NewSchemeOnG1 returns a sign.Scheme that uses G1 for its signature space and G2
// for its public keys
func NewSchemeOnG1(suite pairing.Suite) sign.Scheme {
	sigGroup := suite.G1()
	keyGroup := suite.G2()
	pairing := func(public, hashedMsg, sigPoint kyber.Point) bool {
		return suite.ValidatePairing(hashedMsg, public, sigPoint, keyGroup.Point().Base())
	}
	return &Scheme{
		sigGroup: sigGroup,
		keyGroup: keyGroup,
		pairing:  pairing,
	}
}

// NewSchemeOnG2 returns a sign.Scheme that uses G2 for its signature space and
// G1 for its public key
func NewSchemeOnG2(suite pairing.Suite) sign.Scheme {
	sigGroup := suite.G2()
	keyGroup := suite.G1()
	pairing := func(public, hashedMsg, sigPoint kyber.Point) bool {
		return suite.ValidatePairing(public, hashedMsg, keyGroup.Point().Base(), sigPoint)
	}
	return &Scheme{
		sigGroup: sigGroup,
		keyGroup: keyGroup,
		pairing:  pairing,
	}
}

func (s *Scheme) NewKeyPair(random cipher.Stream) (kyber.Scalar, kyber.Point) {
	secret := s.keyGroup.Scalar().Pick(random)
	public := s.keyGroup.Point().Mul(secret, nil)
	return secret, public
}

func (s *Scheme) NewKeyPairFromPrivateKeyString(str string) (kyber.Scalar, kyber.Point, error) {
	strInt, ok := new(big.Int).SetString(str, 10)
	if !ok {
		return nil, nil, errors.New("failed to parse private key string")
	}
	p, _ := big.NewInt(0).SetString("21888242871839275222246405745257275088696311157297823662689037894645226208583", 10)
	secret := mod.NewInt(strInt, p)
	public := s.keyGroup.Point().Mul(secret, nil)
	return secret, public, nil
}

func (s *Scheme) Sign(private kyber.Scalar, msg []byte) ([]byte, error) {
	hashable, ok := s.sigGroup.Point().(kyber.HashablePoint)
	if !ok {
		return nil, errors.New("point needs to implement hashablePoint")
	}
	HM := hashable.Hash(msg)
	xHM := HM.Mul(private, HM)

	sig, err := xHM.MarshalBinary()
	if err != nil {
		return nil, err
	}
	return sig, nil
}

func (s *Scheme) Verify(X kyber.Point, msg, sig []byte) error {
	hashable, ok := s.sigGroup.Point().(kyber.HashablePoint)
	if !ok {
		return errors.New("bls: point needs to implement hashablePoint")
	}
	HM := hashable.Hash(msg)
	sigPoint := s.sigGroup.Point()
	if err := sigPoint.UnmarshalBinary(sig); err != nil {
		return fmt.Errorf("bls: unmarshalling signature point: %w", err)
	}
	if !s.pairing(X, HM, sigPoint) {
		return errors.New("bls: invalid signature")
	}
	return nil
}
