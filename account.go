package zanolib

type AccountPublicAddr struct {
	SpendKey [32]byte
	ViewKey  [32]byte
	Flags    uint8
}
