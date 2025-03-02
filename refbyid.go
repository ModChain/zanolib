package zanolib

type RefById struct {
	Hash Value256 // source transaction hash
	N    uint32   // output index in source transaction
}
