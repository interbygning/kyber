package pedersen2

import (
	"go.dedis.ch/kyber/v4"
	"go.dedis.ch/kyber/v4/share"
)

type Suite interface {
	kyber.Group
	kyber.HashFactory
	kyber.XOFFactory
	kyber.Random
}

// Phase is a type that represents the different stages of the DKG protocol.
type State int

const (
	InitState State = iota
	DealState
	FinishState
	AbortState
)

func (p State) String() string {
	switch p {
	case InitState:
		return "init"
	case DealState:
		return "deal"
	case FinishState:
		return "finish"
	case AbortState:
		return "abort"
	}
	return "unknown"
}

type Node struct {
	Index  uint32
	Public kyber.Point
}

type DealBundle struct {
	DealerIndex uint32
	Deals       []Deal
	// Public coefficients of the public polynomial used to create the shares
	Public []kyber.Point
	// SessionID of the current run
	SessionID []byte
	// Signature over the hash of the whole bundle
	Signature []byte
}

type Deal struct {
	// Index of the share holder
	ShareIndex uint32
	// encrypted share issued to the share holder
	EncryptedShare []byte
}

type DistKeyShare struct {
	Commits []kyber.Point
	Share   *share.PriShare
}
