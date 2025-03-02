package zanolib

type TxInGen struct {
	Height uint64
}

type TxInZcInput struct {
	// referring_input
	KeyOffsets []*Payload // std::vector<txout_ref_v>; typedef boost::variant<uint64_t, ref_by_id> txout_ref_v
	// txin_zc_input
	KeyImage   [32]byte   // crypto::key_image = ec_point
	EtcDetails []*Payload // std::vector<txin_etc_details_v> = std::vector<boost::variant<signed_parts, extra_attachment_info>>
}
