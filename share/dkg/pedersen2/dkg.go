package pedersen2

import (
	"fmt"

	"go.dedis.ch/kyber/v4"
	"go.dedis.ch/kyber/v4/encrypt/ecies"
	"go.dedis.ch/kyber/v4/group/s256"
	"go.dedis.ch/kyber/v4/pairing/bls12381/kilic"
	"go.dedis.ch/kyber/v4/pairing/bn254"
	"go.dedis.ch/kyber/v4/share"
	"go.dedis.ch/kyber/v4/util/random"
)

// this package is based on the pedersen package in the same directory
// It aims to simplify the protocol, especially remove the eviction, and the
// dynamic QUALified nodes; essentially the protocol aborts if one mandated node
// fails, or if any complaint is reported. This model is more appropriate for
// use where the set of participating nodes are managed elsewhere.

// The protocol has two operations: KeyGen, and ReShare.
// KeyGen protocol: (t-n)-threshold DKG protocol
// 1. Each node generates a random secret and prepare to VSS it with all signers.
// 2. Each node generate a share of the secret for each other node, and a commitment.
// 3. Each node sends the (encrypted) share and commitment to all other nodes.
// 4. Each node verifies the shares and commitments, and if all are valid, the node
//    stores the shares and commitments.
// 5. If any node fails to verify, the protocol aborts.
// 6. If all nodes verify, the protocol completes and the nodes have a distributed
//    key share. Each node can then generate a public key from the shares.

// The communication between the nodes are in a broadcast channel that guarantees
// that all nodes receive the same messages.

// ReShare protocol: (t-n)-threshold DKG protocol
// TODO

type DistKeyGenerator struct {
	state State

	// the following are for authenticating keygen signers; should be on S256 (secp256k1) curve
	// This is because zetachain already uses secp256k1 for signing txs and node ID is based on operator wallet address
	nodeIdSuite  Suite
	nodeIdSecret kyber.Scalar
	nodeIdPublic kyber.Point
	nodes        []Node // all signing nodes in the network
	idx          uint32 // node index; significant as it's the x in lagrange interpolation
	threshold    int    // threshold+1 is the number of nodes needed to reconstruct the secret

	// curve 1: BN254
	suite1 Suite
	dpriv1 *share.PriPoly
	dpub1  *share.PubPoly

	// curve 2: BLS12-381
	suite2 Suite
	dpriv2 *share.PriPoly
	dpub2  *share.PubPoly

	// the valid shares we received; scalar is not dependent on curve
	validShares map[uint32]kyber.Scalar

	// all public polynomials we have seen on two curves; 1 is on BN254, 2 is on BLS12-381
	allPublics1 map[uint32]*share.PubPoly
	allPublics2 map[uint32]*share.PubPoly
}

// If new DKG, this function will create the secret s (dpriv1) and populate the field in result
func NewDistKeyGenerator(idx uint32, threshold int, nodes []Node, nodeIdSecret kyber.Scalar) *DistKeyGenerator {
	suiteId := s256.NewSuite()
	suite1 := bn254.NewSuite()
	suite2 := kilic.NewSuiteBLS12381()

	randomStream := random.New()
	// make sure that the secret fits in the  smaller curve BN254
	secretCoeff := suite1.G1().Scalar().Pick(randomStream)
	dpriv1 := share.NewPriPoly(suite1.G2(), threshold, secretCoeff, randomStream)
	dpub1 := dpriv1.Commit(suite1.G2().Point().Base())
	dpriv2 := share.NewPriPoly(suite2.G2(), threshold, secretCoeff, randomStream)
	dpub2 := dpriv2.Commit(suite2.G2().Point().Base())

	return &DistKeyGenerator{
		state:        InitState,
		nodeIdSuite:  suiteId,
		nodeIdSecret: nodeIdSecret,
		nodeIdPublic: suiteId.Point().Mul(nodeIdSecret, nil),
		nodes:        nodes,
		idx:          idx,
		threshold:    threshold,
		suite1:       suite1,
		dpriv1:       dpriv1,
		dpub1:        dpub1,
		suite2:       suite2,
		dpriv2:       dpriv2,
		dpub2:        dpub2,
		validShares:  make(map[uint32]kyber.Scalar),
		allPublics1:  make(map[uint32]*share.PubPoly),
		allPublics2:  make(map[uint32]*share.PubPoly),
	}
}

// Deal is the first phase of the DKG protocol where the node creates VSS shares and commits
// each node should call this Deal and generate a DealBundle for other nodes (broadcast is fine
// as recipient needs to decrypt their share)
func (gen *DistKeyGenerator) Deal() (*DealBundle, error) {
	deals := make([]Deal, 0, len(gen.nodes))

	for _, node := range gen.nodes {
		// compute share
		si := gen.dpriv1.Eval(node.Index).V

		msg, _ := si.MarshalBinary()
		cipher, err := ecies.Encrypt(gen.nodeIdSuite, node.Public, msg, nil)
		if err != nil {
			return nil, err
		}
		deals = append(deals, Deal{
			ShareIndex:     node.Index,
			EncryptedShare: cipher,
		})
	}
	_, commits := gen.dpub1.Info()
	return &DealBundle{
		DealerIndex: gen.idx,
		Deals:       deals,
		Public:      commits,
		SessionID:   []byte("session-id"),
		Signature:   nil, // no need to sign as the bundle submission is via a tx which already needs to signed.
	}, nil
	//return nil, fmt.Errorf("CANNOT REACH HERE")
}

// When all bundles are available, then process all bundles, compute the local private share,
// and return the public key share
func (gen *DistKeyGenerator) ProcessDealBundles(bundles []*DealBundle) (*DistKeyShare, error) {
	//nodeIdSuite := bn254.NewSuiteG2()
	for _, bundle := range bundles {
		gen.allPublics1[bundle.DealerIndex] = share.NewPubPoly(bn254.NewSuiteG2(), nil, bundle.Public)
	}
	finalShare := gen.nodeIdSuite.Scalar().Zero()
	var err error
	var finalPub *share.PubPoly
	for _, n := range gen.nodes {
		bundle := bundles[n.Index]
		for _, deal := range bundle.Deals {
			if deal.ShareIndex != gen.idx {
				continue
			}
			plain, err := ecies.Decrypt(gen.nodeIdSuite, gen.nodeIdSecret, deal.EncryptedShare, nil)
			if err != nil {
				return nil, err
			}
			sh := gen.nodeIdSuite.Scalar().SetBytes(plain)
			gen.validShares[bundle.DealerIndex] = sh
		}
		sh, ok := gen.validShares[n.Index]
		if !ok {
			return nil, fmt.Errorf("BUG: private share not found from dealer %d", n.Index)
		}

		pub, ok := gen.allPublics1[n.Index]
		if !ok {
			return nil, fmt.Errorf("BUG: idx %d public polynomial not found from dealer %d", gen.idx, n.Index)
		}

		// check if share is valid w.r.t. public commitment
		comm := pub.Eval(gen.idx).V
		G2 := bn254.NewSuiteG2()
		commShare := G2.Point().Mul(sh, nil)
		if !comm.Equal(commShare) {
			return nil, fmt.Errorf("Deal share invalid wrt public poly")
		}

		finalShare = finalShare.Add(finalShare, sh)
		if finalPub == nil {
			finalPub = pub
		} else {
			finalPub, err = finalPub.Add(pub)
			if err != nil {
				return nil, err
			}
		}
	}
	if finalPub == nil {
		return nil, fmt.Errorf("BUG: final public polynomial is nil")
	}
	_, commits := finalPub.Info()
	return &DistKeyShare{
		Commits: commits,
		Share:   &share.PriShare{I: gen.idx, V: finalShare},
	}, nil
}
