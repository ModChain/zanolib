package zanolib

import "fmt"

type AddressType uint64

const (
	PublicAddress           AddressType = 0xc5   // Zx
	PublicIntegAddress      AddressType = 0x3678 // iZ
	PublicIntegAddressV2    AddressType = 0x36f8 // iZ (new format)
	PublicAuditAddress      AddressType = 0x98c8 // aZx
	PublicAuditIntegAddress AddressType = 0x8a49 // aiZX
)

func (a AddressType) String() string {
	switch a {
	case PublicAddress:
		return "Public Address (Zx)"
	case PublicIntegAddress:
		return "Integrated Address (iZ)"
	case PublicIntegAddressV2:
		return "Integrated Address V2 (iZ)"
	case PublicAuditAddress:
		return "Audit Address (aZx)"
	case PublicAuditIntegAddress:
		return "Audit Integrated Address (aiZX)"
	default:
		return fmt.Sprintf("Unknown Address type (%x)", uint64(a))
	}
}

func (a AddressType) Auditable() bool {
	return a == PublicAuditAddress || a == PublicAuditIntegAddress
}

func (a AddressType) HasFlags() bool {
	return a == PublicIntegAddressV2 || a == PublicAuditAddress || a == PublicAuditIntegAddress
}
