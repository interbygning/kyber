package pedersen2

import (
	"testing"

	"go.dedis.ch/kyber/v4"
	"go.dedis.ch/kyber/v4/group/s256"
	"go.dedis.ch/kyber/v4/pairing/bn254"
	"go.dedis.ch/kyber/v4/share"
	"go.dedis.ch/kyber/v4/sign/tbls"
	"go.dedis.ch/kyber/v4/util/random"
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
	pk := distKeys[1].Commits[0]

	for _, dk := range distKeys {
		if !pk.Equal(dk.Commits[0]) {
			t.Fatal("public key not equal")
		}
	}

	// now start to sign one message
	suite := bn254.NewSuiteRand(random.New())
	scheme := tbls.NewThresholdSchemeOnG1(suite)
	//tblScheme := bls.NewSchemeOnG1(nodeIdSuite)
	msg := []byte("Hello BLS")
	sigShares := make([][]byte, 0)
	for _, distKey := range distKeys {
		sig, err := scheme.Sign(distKey.Share, msg)
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("sig(%d): %v", distKey.Share.I, sig)
		sigShares = append(sigShares, sig)

	}
	priShares := make([]*share.PriShare, 0)
	for _, dk := range distKeys {
		priShares = append(priShares, dk.Share)
	}
	secretPoly, err := share.RecoverPriPoly(suite.G2(), priShares, th, n)
	if err != nil {
		t.Fatal(err)
	}
	pubPoly := secretPoly.Commit(suite.G2().Point().Base())
	t.Logf("pubPoly commits: %v", pubPoly.Commit())
	pubPoly2 := share.NewPubPoly(suite.G2(), nil, distKeys[1].Commits)
	t.Logf("distKey commit: %v", pubPoly2.Commit())
	if !pubPoly.Equal(pubPoly2) {
		t.Fatal("public key not equal")
	}
	sig, err := scheme.Recover(pubPoly, msg, sigShares, th, n)
	if err != nil {
		t.Fatal(err)
	}
	err = scheme.VerifyRecovered(pubPoly.Commit(), msg, sig)
	if err != nil {
		t.Fatal(err)
	}
}
