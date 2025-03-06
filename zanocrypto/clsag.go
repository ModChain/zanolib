package zanocrypto

import (
	"crypto/rand"
	"errors"

	"filippo.io/edwards25519"
	"github.com/ModChain/zanolib/zanobase"
)

var (
	CRYPTO_HDS_CLSAG_GGX_LAYER_0   = []byte("ZANO_HDS_CLSAG_GGX_LAYER_ZERO__\x00")
	CRYPTO_HDS_CLSAG_GGX_LAYER_1   = []byte("ZANO_HDS_CLSAG_GGX_LAYER_ONE___\x00")
	CRYPTO_HDS_CLSAG_GGX_LAYER_2   = []byte("ZANO_HDS_CLSAG_GGX_LAYER_TWO___\x00")
	CRYPTO_HDS_CLSAG_GGX_CHALLENGE = []byte("ZANO_HDS_CLSAG_GGX_CHALLENGE___\x00")
)

type CLSAG_GGXInputRef struct {
	StealthAddress   *edwards25519.Point
	AmountCommitment *edwards25519.Point
	BlindedAssetID   *edwards25519.Point
}

func GenerateCLSAG_GGX(
	m []byte,
	ring []CLSAG_GGXInputRef,
	pseudoOutAmountCommitment, pseudoOutBlindedAssetID, ki *edwards25519.Point,
	secret0Xp, secret1F, secret2T *edwards25519.Scalar,
	secretIndex int,
) (*zanobase.CLSAG_Sig, error) {

	ringSize := len(ring)
	if ringSize == 0 {
		return nil, errors.New("ring size is zero")
	}
	if secretIndex < 0 || secretIndex >= ringSize {
		return nil, errors.New("secretIndex out of range")
	}

	// 1) Calculate ki_base = hash_helper_t::hp(ring[secretIndex].stealth_address).
	//    In your C++ code, ring[secretIndex].stealth_address is a point, but then you do hp(...) again,
	//    so presumably it's "HashToPoint(serialized_stealth_address)" or something.  Adjust as needed.
	stealthBytes := ring[secretIndex].StealthAddress.Bytes()
	kiBase := HashToPoint(stealthBytes)

	// 2) key_image = secret_0_xp * ki_base
	keyImage := new(edwards25519.Point).ScalarMult(secret0Xp, kiBase)

	// 3) K1_div8 = (1/8 * secret_1_f) * ki_base
	tmp1 := new(edwards25519.Scalar).Multiply(Sc1div8, secret1F) // sc = c_scalar_1div8 * secret_1_f
	K1_div8 := new(edwards25519.Point).ScalarMult(tmp1, kiBase)

	// Save as sig.K1 (the "public key" portion) => i.e. K1_div8 as a "public key"
	sig := &zanobase.CLSAG_Sig{}
	sig.K1 = &zanobase.Point{new(edwards25519.Point).Set(K1_div8)}

	// Then K1 = K1_div8; K1.modify_mul8() => multiply by 8
	K1 := new(edwards25519.Point).ScalarMult(ScalarInt(8), K1_div8)

	// 4) K2_div8 = (1/8 * secret_2_t) * ki_base
	tmp2 := new(edwards25519.Scalar).Multiply(Sc1div8, secret2T) // sc = c_scalar_1div8 * secret_2_t
	K2_div8 := new(edwards25519.Point).ScalarMult(tmp2, kiBase)

	// Save as sig.K2
	sig.K2 = &zanobase.Point{new(edwards25519.Point).Set(K2_div8)}

	// Then K2 = K2_div8; K2.modify_mul8()
	K2 := new(edwards25519.Point).ScalarMult(ScalarInt(8), K2_div8)

	//----------------------------------------------------------------
	// Next: build up the aggregator hash (the "input_hash")
	//----------------------------------------------------------------
	hsc := newClsagHash()

	// hsc.add_scalar(m) was in C++.  We'll just add m (a raw hash?) as bytes:
	hsc.addBytes(m)

	// for each ring item, add stealth_address, amount_commitment, blinded_asset_id
	for i := 0; i < ringSize; i++ {
		hsc.addPointBytes(ring[i].StealthAddress)
		hsc.addPointBytes(ring[i].AmountCommitment)
		hsc.addPointBytes(ring[i].BlindedAssetID)
	}
	// also add c_scalar_1div8 * pseudoOutAmountCommitment
	tmpPoint := new(edwards25519.Point).ScalarMult(Sc1div8, pseudoOutAmountCommitment)
	hsc.addPointBytes(tmpPoint)

	tmpPoint = new(edwards25519.Point).ScalarMult(Sc1div8, pseudoOutBlindedAssetID)
	hsc.addPointBytes(tmpPoint)

	// add key_image
	hsc.addPointBytes(ki)
	// add K1, K2 (already stored in sig.*)
	hsc.addPointBytes(sig.K1.Point)
	hsc.addPointBytes(sig.K2.Point)

	// input_hash = hsc.calc_hash_no_reduce() in your code
	// We'll assume a single calcHash() usage
	inputHash := hsc.calcHash()

	// For each "layer", you appended some domain-separation bytes, then hashed again.
	// We'll do something like:
	//   hsc.add_32_chars(CRYPTO_HDS_CLSAG_GGX_LAYER_0)
	//   hsc.add_hash(input_hash)
	//   agg_coeff_0 = hsc.calc_hash()
	//
	// In Go, do something similar:
	hsc.addBytes(CRYPTO_HDS_CLSAG_GGX_LAYER_0)
	hsc.addScalarBytes(inputHash) // FIXME check if this doesn't cause issues to mod l the hash
	aggCoeff0 := hsc.calcHash()

	hsc.addBytes(CRYPTO_HDS_CLSAG_GGX_LAYER_1)
	hsc.addScalarBytes(inputHash)
	aggCoeff1 := hsc.calcHash()

	hsc.addBytes(CRYPTO_HDS_CLSAG_GGX_LAYER_2)
	hsc.addScalarBytes(inputHash)
	aggCoeff2 := hsc.calcHash()

	//----------------------------------------------------------------
	// Prepare A_i, Q_i by copying ring[i].amount_commitment and .blinded_asset_id,
	// then multiply each by 8
	//----------------------------------------------------------------
	Ai := make([]*edwards25519.Point, ringSize)
	Qi := make([]*edwards25519.Point, ringSize)
	for i := 0; i < ringSize; i++ {
		Ai[i] = new(edwards25519.Point).ScalarMult(ScalarInt(8), ring[i].AmountCommitment)
		Qi[i] = new(edwards25519.Point).ScalarMult(ScalarInt(8), ring[i].BlindedAssetID)
	}

	//----------------------------------------------------------------
	// Calculate aggregated pubkeys for layer 0 & 1 => W_pub_keys_g,
	// and for layer 2 => W_pub_keys_x
	//----------------------------------------------------------------
	WpubG := make([]*edwards25519.Point, ringSize)
	WpubX := make([]*edwards25519.Point, ringSize)

	for i := 0; i < ringSize; i++ {
		// W_pub_keys_g[i] = agg_coeff_0*stealth + agg_coeff_1*(Ai[i] - pseudoOutAmountCommitment)
		term1 := new(edwards25519.Point).ScalarMult(aggCoeff0, ring[i].StealthAddress)
		diff := new(edwards25519.Point).Subtract(Ai[i], pseudoOutAmountCommitment)
		term2 := new(edwards25519.Point).ScalarMult(aggCoeff1, diff)
		WpubG[i] = new(edwards25519.Point).Add(term1, term2)

		// W_pub_keys_x[i] = agg_coeff_2*(Qi[i] - pseudoOutBlindedAssetID)
		diff2 := new(edwards25519.Point).Subtract(Qi[i], pseudoOutBlindedAssetID)
		WpubX[i] = new(edwards25519.Point).ScalarMult(aggCoeff2, diff2)
	}

	//----------------------------------------------------------------
	// Aggregate secret keys
	//----------------------------------------------------------------
	// w_sec_key_g = agg_coeff_0*secret_0_xp + agg_coeff_1*secret_1_f
	wSecKeyG := new(edwards25519.Scalar).Multiply(aggCoeff0, secret0Xp)
	wSecKeyG = new(edwards25519.Scalar).Add(wSecKeyG, new(edwards25519.Scalar).Multiply(aggCoeff1, secret1F))

	// w_sec_key_x = agg_coeff_2*secret_2_t
	wSecKeyX := new(edwards25519.Scalar).Multiply(aggCoeff2, secret2T)

	//----------------------------------------------------------------
	// Aggregate key images
	//----------------------------------------------------------------
	// W_key_image_g = agg_coeff_0*key_image + agg_coeff_1*K1
	WkeyImageGPart1 := new(edwards25519.Point).ScalarMult(aggCoeff0, keyImage)
	WkeyImageGPart2 := new(edwards25519.Point).ScalarMult(aggCoeff1, K1)
	WkeyImageG := new(edwards25519.Point).Add(WkeyImageGPart1, WkeyImageGPart2)

	// W_key_image_x = agg_coeff_2*K2
	WkeyImageX := new(edwards25519.Point).ScalarMult(aggCoeff2, K2)

	//----------------------------------------------------------------
	// Initial commitment: alpha_g, alpha_x are random scalars
	//----------------------------------------------------------------
	alphaG := RandomScalar(rand.Reader)
	alphaX := RandomScalar(rand.Reader)

	// c_prev = Hs(input_hash, alpha_g*G, alpha_g*ki_base, alpha_x*X, alpha_x*ki_base)
	// We'll reuse the hasher or create a new one (depending on your approach).
	hsc = newClsagHash()
	hsc.addBytes(CRYPTO_HDS_CLSAG_GGX_CHALLENGE)
	hsc.addScalarBytes(inputHash)

	hsc.addPointBytes(new(edwards25519.Point).ScalarMult(alphaG, C_point_G))
	hsc.addPointBytes(new(edwards25519.Point).ScalarMult(alphaG, kiBase))
	hsc.addPointBytes(new(edwards25519.Point).ScalarMult(alphaX, C_point_X))
	hsc.addPointBytes(new(edwards25519.Point).ScalarMult(alphaX, kiBase))
	cPrev := hsc.calcHash()

	//----------------------------------------------------------------
	// Initialize sig.Rg and sig.Rx with random scalars (just like the C++ code)
	//----------------------------------------------------------------
	sig.Rg = make([]*zanobase.Scalar, ringSize)
	sig.Rx = make([]*zanobase.Scalar, ringSize)
	for i := 0; i < ringSize; i++ {
		sig.Rg[i] = &zanobase.Scalar{RandomScalar(rand.Reader)}
		sig.Rx[i] = &zanobase.Scalar{RandomScalar(rand.Reader)}
	}

	//----------------------------------------------------------------
	// The main ring loop
	//----------------------------------------------------------------
	i := (secretIndex + 1) % ringSize
	for j := 0; j < ringSize-1; j++ {
		// if i == 0 => sig.c = cPrev
		if i == 0 {
			sig.C = &zanobase.Scalar{new(edwards25519.Scalar).Set(cPrev)}
		}

		// c_{i+1} = Hs(input_hash, r_g[i]*G + c_prev*W_pub_keys_g[i],
		//                        r_g[i]*hp(ring[i].stealth_address) + c_prev*W_key_image_g,
		//                        r_x[i]*X + c_prev*W_pub_keys_x[i],
		//                        r_x[i]*hp(ring[i].stealth_address) + c_prev*W_key_image_x )
		hsc = newClsagHash()
		hsc.addBytes([]byte("CRYPTO_HDS_CLSAG_GGX_CHALLENGE"))
		hsc.addScalarBytes(inputHash)

		// 1) r_g[i]*G + c_prev*W_pub_keys_g[i]
		rgG := new(edwards25519.Point).ScalarMult(sig.Rg[i].Scalar, C_point_G)
		cwpg := new(edwards25519.Point).ScalarMult(cPrev, WpubG[i])
		hsc.addPointBytes(new(edwards25519.Point).Add(rgG, cwpg))

		// 2) r_g[i]*hp(stealth) + c_prev*W_key_image_g
		stealthBytes2 := ring[i].StealthAddress.Bytes()
		hpI := HashToPoint(stealthBytes2)

		rgHp := new(edwards25519.Point).ScalarMult(sig.Rg[i].Scalar, hpI)
		cwikg := new(edwards25519.Point).ScalarMult(cPrev, WkeyImageG)
		hsc.addPointBytes(new(edwards25519.Point).Add(rgHp, cwikg))

		// 3) r_x[i]*X + c_prev*W_pub_keys_x[i]
		rxX := new(edwards25519.Point).ScalarMult(sig.Rx[i].Scalar, C_point_X)
		cwpx := new(edwards25519.Point).ScalarMult(cPrev, WpubX[i])
		hsc.addPointBytes(new(edwards25519.Point).Add(rxX, cwpx))

		// 4) r_x[i]*hp(stealth) + c_prev*W_key_image_x
		rxHp := new(edwards25519.Point).ScalarMult(sig.Rx[i].Scalar, hpI)
		cwikx := new(edwards25519.Point).ScalarMult(cPrev, WkeyImageX)
		hsc.addPointBytes(new(edwards25519.Point).Add(rxHp, cwikx))

		cPrev = hsc.calcHash()

		i = (i + 1) % ringSize
	}

	// Finally, for c[secretIndex] = c_prev
	if secretIndex == 0 {
		sig.C = &zanobase.Scalar{new(edwards25519.Scalar).Set(cPrev)}
	}

	// sig.r_g[secretIndex] = alpha_g - c_prev * w_sec_key_g
	rgSecretIndex := new(edwards25519.Scalar).Subtract(alphaG, new(edwards25519.Scalar).Multiply(cPrev, wSecKeyG))
	sig.Rg[secretIndex] = &zanobase.Scalar{rgSecretIndex}

	// sig.r_x[secretIndex] = alpha_x - c_prev * w_sec_key_x
	rxSecretIndex := new(edwards25519.Scalar).Subtract(alphaX, new(edwards25519.Scalar).Multiply(cPrev, wSecKeyX))
	sig.Rx[secretIndex] = &zanobase.Scalar{rxSecretIndex}

	return sig, nil
}
