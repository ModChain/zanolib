package zanolib

import (
	"github.com/ModChain/edwards25519"
)

// ComputeKeyImage computes the key image for a given spend key.
func ComputeKeyImage(spendPriv []byte, spendPub *edwards25519.PublicKey) ([32]byte, error) {
	var image [32]byte
	// hash_to_ec(pub, point);
	point, err := HashToEC(spendPub)
	if err != nil {
		return image, err
	}

	var secBytes [32]byte
	copy(secBytes[:], spendPriv)

	// ge_scalarmult(&point2, &sec, &point);
	var zero [32]byte
	var proj edwards25519.ProjectiveGroupElement
	edwards25519.GeDoubleScalarMultVartime(&proj, &secBytes, point, &zero)

	// 4) Serialize the ProjectiveGroupElement to 32 bytes (equivalent to ge_tobytes).
	proj.ToBytes(&image)

	return image, nil
}
