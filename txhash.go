package zanolib

import (
	"github.com/ModChain/zanolib/zanobase"
	"golang.org/x/crypto/sha3"
)

func GetTransactionPrefixHash(tx *zanobase.Transaction) ([]byte, error) {
	h := sha3.NewLegacyKeccak256()
	err := Serialize(h, tx.Prefix())
	return h.Sum(nil), err
}

func PreparePrefixHashForSign(tx *zanobase.Transaction, inIndex int, txId []byte) ([]byte, error) {
	// TODO get_tx_flags(tx) & TX_FLAG_SIGNATURE_MODE_SEPARATE
	return txId, nil
}
