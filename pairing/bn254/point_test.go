package bn254

import (
	"bytes"
	"encoding/hex"
	"math/big"
	"testing"
)

func TestSqrt(t *testing.T) {
	// test vectors from
	q := big.NewInt(0)
	// this is (p+1)/4
	q.SetString("c19139cb84c680a6e14116da060561765e05aa45a1c72a34f082305b61f3f52", 16)
	t.Logf("q: %s", q.Text(10))
	t.Logf("p: %s", p.Text(10))

	y, err := big.NewInt(0).SetString("3793767019703003364522970305881959608533388291937108457030659789191024893920", 10)
	if !err {
		t.Fatal("failed to set big int")
	}
	t.Logf("y: %s", y.Text(10))
	y2 := new(big.Int).Exp(y, q, p)
	t.Logf("y2: %s", y2.Text(10))
	y2 = new(big.Int).Mul(y2, y2)
	y2 = new(big.Int).Mod(y2, p)
	t.Logf("y2: %s", y2.Text(10))

	hashPoint := hashToPointHashAndPray([]byte("Hello BLS"))
	t.Logf("hashPoint: %s", hashPoint)
}

func TestPointG1_HashToPoint(t *testing.T) {
	domain := []byte("domain_separation_tag_test_12345")

	// reference test 1
	p := newPointG1(domain).Hash([]byte("Hello BLS"))
	pBuf, err := p.MarshalBinary()
	if err != nil {
		t.Error(err)
	}
	t.Logf("hash %x", pBuf)
	// reference from Solidity and its hash and pray implementation
	//>> hex(5987718135985124777279747422376396745080763197674376990450444442288119654198)
	//'0xd3ceda962c2e6e008682be2f86da855c6a7f9ea33a10570cc5e4dd7b710a736'
	//>>> hex(6997241657768735445093763087414958605667071248301947314582032744388594841245)
	//'0xf784c65f2cbae4dad543bb9fb91306ab6d79bc2503d22854c763e860b2d369d'

	refBuf, err := hex.DecodeString("0d3ceda962c2e6e008682be2f86da855c6a7f9ea33a10570cc5e4dd7b710a7360f784c65f2cbae4dad543bb9fb91306ab6d79bc2503d22854c763e860b2d369d")
	if err != nil {
		t.Error(err)
	}
	t.Logf("ref %x", refBuf)
	if !bytes.Equal(pBuf, refBuf) {
		t.Error("hash does not match reference")
	}

}
