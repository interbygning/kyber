package pedersen2

import (
	"testing"

	"go.dedis.ch/kyber/v4"
	"go.dedis.ch/kyber/v4/group/s256"
	"go.dedis.ch/kyber/v4/share"
	"go.dedis.ch/kyber/v4/sign/tbls"
)

type Network struct {
	Generators []*DistKeyGenerator
	Suite      kyber.Group
}

func NewNetwork(t, n int) *Network {
	suite := s256.NewSuite()
	//nodeIdSuite := bn254.NewSuite()
	nodes := make([]Node, n)
	secrets := []kyber.Scalar{}
	for i := 0; i < n; i++ {
		// create secret
		nodeIdSecret := suite.Scalar().Pick(suite.RandomStream())
		secrets = append(secrets, nodeIdSecret)
		nodes[i] = Node{
			Index:  uint32(i),
			Public: suite.Point().Mul(nodeIdSecret, nil),
		}
	}
	generators := make([]*DistKeyGenerator, n)
	for i := 0; i < n; i++ {
		generators[i] = NewDistKeyGenerator(uint32(i), t, nodes, secrets[i])
	}
	return &Network{
		Generators: generators,
		Suite:      suite,
	}
}

func TestDKGNew(t *testing.T) {
	th := 3
	n := 5
	net := NewNetwork(th, n)
	bundles := make([]*DealBundle, n)
	for _, node := range net.Generators {
		if node == nil {
			t.Fatal("node is nil")
		}
		bundle, err := node.Deal()
		if err != nil {
			t.Fatal(err)
		}
		bundles[node.idx] = bundle
	}

	distKeys := make([]*DistKeyShare, n)
	for _, gen := range net.Generators {
		if gen == nil {
			t.Fatal("gen is nil")
		}
		distKey, err := gen.ProcessDealBundles(bundles)
		if err != nil {
			t.Fatal(err)
		}
		distKeys[gen.idx] = distKey

	}
	// make sure all public keys are the same
	pk := distKeys[1].Commits1[0]

	for _, dk := range distKeys {
		if !pk.Equal(dk.Commits1[0]) {
			t.Fatal("public key not equal")
		}
	}

	//tblScheme := bls.NewSchemeOnG1(nodeIdSuite)
	gen := net.Generators[0]
	scheme1 := tbls.NewThresholdSchemeOnG1(gen.suite1)
	scheme2 := tbls.NewThresholdSchemeOnG1(gen.suite2)
	msg := []byte("Hello BLS")
	sigShares1 := make([][]byte, 0)
	sigShares2 := make([][]byte, 0)
	for _, distKey := range distKeys {
		sig, err := scheme1.Sign(distKey.Share1, msg)
		if err != nil {
			t.Fatal(err)
		}
		sigShares1 = append(sigShares1, sig)

		sig, err = scheme2.Sign(distKey.Share2, msg)
		if err != nil {
			t.Fatal(err)
		}
		sigShares2 = append(sigShares2, sig)
	}
	priShares1 := make([]*share.PriShare, 0)
	for _, dk := range distKeys {
		priShares1 = append(priShares1, dk.Share1)
	}
	secretPoly, err := share.RecoverPriPoly(gen.suite1.G2(), priShares1, th, n)
	if err != nil {
		t.Fatal(err)
	}
	pubPolyExp := secretPoly.Commit(gen.suite1.G2().Point().Base())
	pubPoly := share.NewPubPoly(gen.suite1.G2(), nil, distKeys[1].Commits1)
	if !pubPoly.Equal(pubPolyExp) {
		t.Fatal("public key not equal")
	}

	sig, err := scheme1.Recover(pubPoly, msg, sigShares1, th, n)
	if err != nil {
		t.Fatal(err)
	}
	err = scheme1.VerifyRecovered(pubPoly.Commit(), msg, sig)
	if err != nil {
		t.Fatal(err)
	}

	pubPoly2 := share.NewPubPoly(gen.suite2.G2(), nil, distKeys[1].Commits2)

	sig, err = scheme2.Recover(pubPoly2, msg, sigShares2, th, n)
	if err != nil {
		t.Fatal(err)
	}

	err = scheme2.VerifyRecovered(pubPoly2.Commit(), msg, sig)
	if err != nil {
		t.Fatal(err)
	}

	t.Logf("BN254 public key: %v", pubPoly.Commit())
	t.Logf("BLS12-381 public key: %v", pubPoly2.Commit())
}
