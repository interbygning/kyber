package s256

import (
	"testing"

	"go.dedis.ch/kyber/v4/util/random"
)

func Test1(t *testing.T) {
	suite := NewSuite()
	t.Logf("ScalarLen: %d", suite.ScalarLen())

	p := suite.Point().Pick(random.New())
	t.Logf("Point: %s", p)

	s := suite.Scalar().Pick(random.New())
	t.Logf("Scalar: %s", s)

	S := suite.Point().Mul(s, suite.Point().Base())
	t.Logf("Scalar*Point: %s", S)

}
