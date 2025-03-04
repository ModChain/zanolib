package zanocrypto

import (
	"errors"
	"slices"

	"github.com/ModChain/edwards25519"
	"github.com/ModChain/zanolib/zanobase"
)

func DerivePublicKey(derivation [32]byte, outputIndex uint64, basePublic *[32]byte) (*[32]byte, error) {
	// derivation_to_scalar basically concats derivation and varint(outputIndex)
	scalar := HashToScalar(slices.Concat(derivation[:], zanobase.Varint(outputIndex).Bytes()))

	// Convert spend_public_key to an ExtendedGroupElement
	var spendPubPoint edwards25519.ExtendedGroupElement
	if !spendPubPoint.FromBytes(basePublic) {
		// invalid spend public key encoding
		return nil, errors.New("invalid spend public key encoding")
	}

	// point2 = scalar * G  (GeScalarMultBase)
	var point2 edwards25519.ExtendedGroupElement
	edwards25519.GeScalarMultBase(&point2, &scalar)

	// ephemeralPubPoint = spendPubPoint + point2
	var spendPubCached edwards25519.CachedGroupElement
	spendPubPoint.ToCached(&spendPubCached)

	var sumCompleted edwards25519.CompletedGroupElement
	edwards25519.GeAdd(&sumCompleted, &point2, &spendPubCached)

	var ephemeralPubPoint edwards25519.ExtendedGroupElement
	sumCompleted.ToExtended(&ephemeralPubPoint)

	var res [32]byte
	// Write ephemeralPubPoint into inEphemeral.Pub
	ephemeralPubPoint.ToBytes(&res)

	return &res, nil
}
