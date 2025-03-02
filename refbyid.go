package zanolib

type RefById struct {
	Hash [32]byte // source transaction hash
	N    uint32   // output index in source transaction
}
