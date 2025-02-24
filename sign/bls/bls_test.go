package bls

import (
	"fmt"
	"math/big"
	"testing"

	"github.com/stretchr/testify/require"
	"go.dedis.ch/kyber/v4/pairing/bls12381/kilic"
	"go.dedis.ch/kyber/v4/pairing/bn254"
	"go.dedis.ch/kyber/v4/pairing/bn256"
	"go.dedis.ch/kyber/v4/util/random"
)

func TestBLS(t *testing.T) {
	suite := bn254.NewSuite()
	msg := []byte("Hello BLS")
	BLSRoutine(t, msg, suite)
}

func TestBLS12381(t *testing.T) {
	suite := kilic.NewBLS12381Suite()
	msg := []byte("Hello BLS")
	scheme := NewSchemeOnG1(suite)
	private, public, err := scheme.NewKeyPairFromPrivateKeyString("5532719355993668376817313988550233634227690018686483329169046691728862458102")
	require.Nil(t, err)
	sig, err := scheme.Sign(private, msg)
	require.Nil(t, err)
	fmt.Printf("sig(len %d) hex: %x\n", len(sig), sig)
	pkBin, err := public.MarshalBinary()
	require.Nil(t, err)
	fmt.Printf("public(len %d) hex: %x\n", len(pkBin), pkBin)
	err = scheme.Verify(public, msg, sig)
	require.Nil(t, err)
}

func FuzzBLS(f *testing.F) {
	suite := bn254.NewSuite()
	f.Fuzz(func(t *testing.T, msg []byte) {
		if len(msg) < 1 || len(msg) > 1000 {
			t.Skip("msg must have byte length between 1 and 1000")
		}
		BLSRoutine(t, msg, suite)
	})
}

func BLSRoutine(t *testing.T, msg []byte, suite *bn254.Suite) {
	scheme := NewSchemeOnG1(suite)
	//private, public := scheme.NewKeyPair(blake2xb.New(msg))
	// this is to match a private key generated in solidity test code
	private, public, err := scheme.NewKeyPairFromPrivateKeyString("5532719355993668376817313988550233634227690018686483329169046691728862458102")
	require.Nil(t, err)
	//fmt.Printf("public(len %d) hex: %x")
	sig, err := scheme.Sign(private, msg)
	require.Nil(t, err)
	sigx := big.NewInt(0).SetBytes(sig[:32])
	sigy := big.NewInt(0).SetBytes(sig[32:])
	//fmt.Printf("sig(len %d) hex: %x\n", len(sig), sig)
	fmt.Printf("sigx num: %d\n", sigx)
	fmt.Printf("sigy num: %d\n", sigy)
	err = scheme.Verify(public, msg, sig)
	require.Nil(t, err)
	fmt.Println(public)
}

func TestBLSFailSig(t *testing.T) {
	msg := []byte("Hello Boneh-Lynn-Shacham")
	suite := bn256.NewSuite()
	scheme := NewSchemeOnG1(suite)
	private, public := scheme.NewKeyPair(random.New())
	sig, err := scheme.Sign(private, msg)
	require.Nil(t, err)
	sig[0] ^= 0x01
	if scheme.Verify(public, msg, sig) == nil {
		t.Fatal("bls: verification succeeded unexpectedly")
	}
}

func TestBLSFailKey(t *testing.T) {
	msg := []byte("Hello Boneh-Lynn-Shacham")
	suite := bn256.NewSuite()
	scheme := NewSchemeOnG1(suite)
	private, _ := scheme.NewKeyPair(random.New())
	sig, err := scheme.Sign(private, msg)
	require.Nil(t, err)
	_, public := scheme.NewKeyPair(random.New())
	if scheme.Verify(public, msg, sig) == nil {
		t.Fatal("bls: verification succeeded unexpectedly")
	}
}

func BenchmarkBLSKeyCreation(b *testing.B) {
	suite := bn256.NewSuite()
	scheme := NewSchemeOnG1(suite)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		scheme.NewKeyPair(random.New())
	}
}

func BenchmarkBLSSign(b *testing.B) {
	suite := bn256.NewSuite()
	scheme := NewSchemeOnG1(suite)
	private, _ := scheme.NewKeyPair(random.New())
	msg := []byte("Hello many times Boneh-Lynn-Shacham")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := scheme.Sign(private, msg)
		require.Nil(b, err)
	}
}
