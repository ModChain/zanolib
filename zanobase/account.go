package zanobase

type AccountPublicAddr struct {
	SpendKey Value256
	ViewKey  Value256
	Flags    uint8
}
