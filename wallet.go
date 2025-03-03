package zanolib

import (
	"slices"

	"github.com/ModChain/edwards25519"
	"golang.org/x/crypto/sha3"
)

type Wallet struct {
	SpendPrivKey *edwards25519.PrivateKey
	SpendPubKey  *edwards25519.PublicKey
	ViewPrivKey  *edwards25519.PrivateKey
	ViewPubKey   *edwards25519.PublicKey
	Flags        uint8 // flag 1 = auditable
}

// LoadSpendSecret initializesd a Wallet based on a spend secret as found in
// zano if you run spendkey. Note that zano's displayed key is in little endian
// so this function will reverse the bytes for you.
func LoadSpendSecret(pk []byte, Flags uint8) (*Wallet, error) {
	pk = slices.Clone(pk)
	viewKey := hsum(sha3.NewLegacyKeccak256, pk)
	slices.Reverse(pk)
	priv, pub, err := edwards25519.PrivKeyFromScalar(pk)
	if err != nil {
		return nil, err
	}

	// load view key
	ScReduce32(viewKey)
	slices.Reverse(viewKey)
	vpriv, vpub, err := edwards25519.PrivKeyFromScalar(viewKey)
	if err != nil {
		return nil, err
	}

	res := &Wallet{
		SpendPrivKey: priv,
		SpendPubKey:  pub,
		ViewPrivKey:  vpriv,
		ViewPubKey:   vpub,
	}
	//log.Printf("spend pub = %x", pub.Serialize())
	//log.Printf("view pub = %x", vpub.Serialize())
	//log.Printf("addr = %s", res.Address())

	return res, nil
}

// Address returns this wallet's address.
func (w *Wallet) Address() *Address {
	typ := PublicAddress
	if w.Flags&1 == 1 {
		typ = PublicAuditAddress
	}

	addr := &Address{
		Type:     typ,
		Flags:    w.Flags,
		SpendKey: w.SpendPubKey.Serialize(),
		ViewKey:  w.ViewPubKey.Serialize(),
	}

	return addr
}
