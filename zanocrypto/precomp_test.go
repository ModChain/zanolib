package zanocrypto_test

import (
	"testing"

	"github.com/ModChain/edwards25519"
	"github.com/ModChain/zanolib/zanocrypto"
)

// ensure precomputed values are correct

func TestPrecomp(t *testing.T) {
	testPrecompVar(t, "H", zanocrypto.C_point_H, c_point_H_precomp_data)
	testPrecompVar(t, "H2", zanocrypto.C_point_H2, c_point_H2_precomp_data)
	testPrecompVar(t, "U", zanocrypto.C_point_U, c_point_U_precomp_data)
	testPrecompVar(t, "X", zanocrypto.C_point_X, c_point_X_precomp_data)
	testPrecompVar(t, "H_plus_G", zanocrypto.C_point_H_plus_G, c_point_H_plus_G_precomp_data)
	testPrecompVar(t, "H_minus_G", zanocrypto.C_point_H_minus_G, c_point_H_minus_G_precomp_data)
}

func testPrecompVar(t *testing.T, name string, point *edwards25519.ExtendedGroupElement, data precompData) {
	// compute point
	goodPoint := data.extended()
	// make sure point == goodPoint
	if point == nil || *point != *goodPoint {
		t.Errorf("point %s cached data is wrong: %#v", name, goodPoint)
	}
}
