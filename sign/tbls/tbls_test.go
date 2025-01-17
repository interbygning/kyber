package tbls

import (
	"errors"
	"fmt"
	"math/big"
	"testing"

	"github.com/stretchr/testify/require"
	"go.dedis.ch/kyber/v4/group/mod"
	"go.dedis.ch/kyber/v4/internal/test"
	"go.dedis.ch/kyber/v4/pairing/bn254"
	"go.dedis.ch/kyber/v4/pairing/bn256"
	"go.dedis.ch/kyber/v4/share"
	"go.dedis.ch/kyber/v4/sign/bls"
	"go.dedis.ch/kyber/v4/xof/blake2xb"
)

func TestTBLS(test *testing.T) {
	msg := []byte("Hello BLS")
	TBLSRoutine(test, msg, 10)
}

func FuzzTBLS(f *testing.F) {
	f.Fuzz(func(t *testing.T, msg []byte, n int) {
		if (n < 1) || (n > 100) {
			t.Skip("n must be between 1 and 100")
		}
		if (len(msg) < 1) || (len(msg) > 1000) {
			t.Skip("msg must have byte length between 1 and 1000")
		}
		TBLSRoutine(t, msg, n)
	})
}

func TBLSRoutine(test *testing.T, msg []byte, n int) {
	// Use a deterministic seed for the random stream
	stream := blake2xb.New(msg)
	suite := bn254.NewSuiteRand(stream)
	scheme := NewThresholdSchemeOnG1(suite)
	th := n/2 + 1

	//secret := suite.G1().Scalar().Pick(stream)
	str := "5532719355993668376817313988550233634227690018686483329169046691728862458102"
	strInt, ok := new(big.Int).SetString(str, 10)
	if !ok {
		require.Nil(test, errors.New("failed to parse private key string"))
	}
	p, _ := big.NewInt(0).SetString("21888242871839275222246405745257275088696311157297823662689037894645226208583", 10)
	secret := mod.NewInt(strInt, p)
	fmt.Printf("private key: %d\n", strInt)

	priPoly := share.NewPriPoly(suite.G2(), th, secret, stream)
	pubPoly := priPoly.Commit(suite.G2().Point().Base())
	ps := pubPoly.Commit() // this is the public key
	fmt.Println("public key share:", ps)
	//fmt.Println(reflect.TypeOf(ps))
	sigShares := make([][]byte, 0)

	for _, x := range priPoly.Shares(n) {
		sig, err := scheme.Sign(x, msg)
		require.Nil(test, err)
		sigShares = append(sigShares, sig)
	}

	sig, err := scheme.Recover(pubPoly, msg, sigShares, th, n)
	require.Nil(test, err)
	sigx := big.NewInt(0).SetBytes(sig[:32])
	sigy := big.NewInt(0).SetBytes(sig[32:])
	//fmt.Printf("sig(len %d) hex: %x\n", len(sig), sig)
	fmt.Printf("sigx num: %d\n", sigx)
	fmt.Printf("sigy num: %d\n", sigy)

	err = scheme.VerifyRecovered(pubPoly.Commit(), msg, sig)
	require.Nil(test, err)

	sheme2 := bls.NewSchemeOnG1(suite)
	err = sheme2.Verify(ps, msg, sig)
	require.Nil(test, err)
}

func TestBN256(t *testing.T) {
	suite := bn256.NewSuite()
	scheme := NewThresholdSchemeOnG1(suite)
	test.ThresholdTest(t, suite.G2(), scheme)
}
