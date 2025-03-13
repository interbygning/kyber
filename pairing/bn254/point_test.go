package bn254

import (
	"bytes"
	"encoding/hex"
	"errors"
	"math/big"
	"testing"

	"golang.org/x/crypto/sha3"
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

	//// reference test 2
	//buf2, err := hex.DecodeString("e0a05cbb37fd6c159732a8c57b981773f7480695328b674d8a9cc083377f1811")
	//if err != nil {
	//	t.Error(err)
	//}
	//p2 := newPointG1(domain).Hash(buf2)
	//p2Buf, err := p2.MarshalBinary()
	//if err != nil {
	//	t.Error(err)
	//}
	//refBuf2, err := hex.DecodeString("07abd743dc93dfa3a8ee4ab449b1657dc6232c589612b23a54ea461c7232101e2533badbee56e8457731fc35bb7630236623e4614e4f8acb4a0c3282df58a289")
	//if err != nil {
	//	t.Error(err)
	//}
	//if !bytes.Equal(p2Buf, refBuf2) {
	//	t.Error("hash does not match reference")
	//}
}

func TestExpandMsg(t *testing.T) {
	dst := []byte("BLS_SIG_BN254G1_XMD:KECCAK-256_SSWU_RO_NUL_")
	msg, err := hex.DecodeString("af6c1f30b2f3f2fd448193f90d6fb55b544a")
	if err != nil {
		t.Error("decode errored", err.Error())
	}

	expanded := expandMsgXmdKeccak256(
		dst,
		msg,
		96,
	)
	if err != nil {
		t.Error("expandMsgXmdKeccak256 errored", err.Error())
	}

	// Output from Solidity & ts implementation in bls-bn254
	if hex.EncodeToString(expanded) != "bd365d9672926bbb6887f8c0ce88d1edc0c20bd46f6af54e80c7edc15ac1c5eba9e754994af715195aa8acb3f21febae2b9626bc1b06c185922455908d1c8db3d370fe339995718e344af3add0aa77d3bd48d0d9f3ebe26b88cbb393325c1c6e" {
		t.Error("expandMsgXmdKeccak256 does not match ref", hex.EncodeToString(expanded))
	}

	// Sanity check against gnark's implementation
	gnarkExpanded, err := gnarkExpandMsgXmd(msg, dst, 96)
	if err != nil {
		t.Error("gnarkExpandMsgXmd errored", err.Error())
	}
	if hex.EncodeToString(expanded) != hex.EncodeToString(gnarkExpanded) {
		t.Error("expandMsgXmdKeccak256 did not match gnark implementation")
	}
}

func TestHashToField(t *testing.T) {
	dst := []byte("BLS_SIG_BN254G1_XMD:KECCAK-256_SSWU_RO_NUL_")
	for i, testVector := range hashToFieldTestVectors {
		_msg, err := hex.DecodeString(testVector.Msg)
		if err != nil {
			t.Error("decode errored", err.Error())
		}

		x, y := hashToField(
			dst,
			_msg,
		)

		if x.String() != testVector.RefX {
			t.Errorf("[%d] hashToField x does not match ref %s != %s", i, x, testVector.RefX)
		}
		if y.String() != testVector.RefY {
			t.Errorf("[%d] hashToField y does not match ref %s != %s", i, y, testVector.RefY)
		}
	}
}

func TestMapToPoint(t *testing.T) {
	dst := []byte("BN254G1_XMD:KECCAK-256_SVDW_RO_NUL_")

	for i, testVector := range mapToPointTestVectors {
		u := newGFpFromBase10(testVector.U)
		pRef := newPointG1(dst).Base().(*pointG1)
		pRef.g.x.Set(newGFpFromBase10(testVector.RefX))
		pRef.g.y.Set(newGFpFromBase10(testVector.RefY))

		p := mapToPoint(dst, u).(*pointG1)

		if !p.Equal(pRef) {
			t.Errorf("[%d] point does not match ref (%s != %s)", i, p.String(), pRef.String())
		}
	}
}

// Borrowed from: https://github.com/Consensys/gnark-crypto/blob/18aa16f0fde4c13d8a7d3806bf13d70b6b5d4cb6/field/hash/hashutils.go
// The first line instantiating the hashing function has been changed from sha256 to keccak256.
// This is here to sanity check against our actual implementation.
//
// ExpandMsgXmd expands msg to a slice of lenInBytes bytes.
// https://datatracker.ietf.org/doc/html/rfc9380#name-expand_message_xmd
// https://datatracker.ietf.org/doc/html/rfc9380#name-utility-functions (I2OSP/O2ISP)
func gnarkExpandMsgXmd(msg, dst []byte, lenInBytes int) ([]byte, error) {

	h := sha3.NewLegacyKeccak256()
	ell := (lenInBytes + h.Size() - 1) / h.Size() // ceil(len_in_bytes / b_in_bytes)
	if ell > 255 {
		return nil, errors.New("invalid lenInBytes")
	}
	if len(dst) > 255 {
		return nil, errors.New("invalid domain size (>255 bytes)")
	}
	sizeDomain := uint8(len(dst))

	// Z_pad = I2OSP(0, r_in_bytes)
	// l_i_b_str = I2OSP(len_in_bytes, 2)
	// DST_prime = DST ∥ I2OSP(len(DST), 1)
	// b₀ = H(Z_pad ∥ msg ∥ l_i_b_str ∥ I2OSP(0, 1) ∥ DST_prime)
	h.Reset()
	if _, err := h.Write(make([]byte, h.BlockSize())); err != nil {
		return nil, err
	}
	if _, err := h.Write(msg); err != nil {
		return nil, err
	}
	if _, err := h.Write([]byte{uint8(lenInBytes >> 8), uint8(lenInBytes), uint8(0)}); err != nil {
		return nil, err
	}
	if _, err := h.Write(dst); err != nil {
		return nil, err
	}
	if _, err := h.Write([]byte{sizeDomain}); err != nil {
		return nil, err
	}
	b0 := h.Sum(nil)

	// b₁ = H(b₀ ∥ I2OSP(1, 1) ∥ DST_prime)
	h.Reset()
	if _, err := h.Write(b0); err != nil {
		return nil, err
	}
	if _, err := h.Write([]byte{uint8(1)}); err != nil {
		return nil, err
	}
	if _, err := h.Write(dst); err != nil {
		return nil, err
	}
	if _, err := h.Write([]byte{sizeDomain}); err != nil {
		return nil, err
	}
	b1 := h.Sum(nil)

	res := make([]byte, lenInBytes)
	copy(res[:h.Size()], b1)

	for i := 2; i <= ell; i++ {
		// b_i = H(strxor(b₀, b_(i - 1)) ∥ I2OSP(i, 1) ∥ DST_prime)
		h.Reset()
		strxor := make([]byte, h.Size())
		for j := 0; j < h.Size(); j++ {
			strxor[j] = b0[j] ^ b1[j]
		}
		if _, err := h.Write(strxor); err != nil {
			return nil, err
		}
		if _, err := h.Write([]byte{uint8(i)}); err != nil {
			return nil, err
		}
		if _, err := h.Write(dst); err != nil {
			return nil, err
		}
		if _, err := h.Write([]byte{sizeDomain}); err != nil {
			return nil, err
		}
		b1 = h.Sum(nil)
		copy(res[h.Size()*(i-1):min(h.Size()*i, len(res))], b1)
	}
	return res, nil
}
