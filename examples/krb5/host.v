// HostAddress     ::= SEQUENCE  {
//           addr-type       [0] Int32,
//           address         [1] OCTET STRING
//   }
struct HostAddress {
	addr_type int
	address   asn1.OctetString
}

fn (ha HostAddress) encode(mut out []u8) ! {
	mut seq := asn1.Sequence.new(false)!
	el1 := asn1.Integer.from_i64(ha.addr_type)!
	ctx1 := asn1.TaggedType.explicit_context(el1, 0)!
	ctx2 := asn1.TaggedType.explicit_context(ha.address, 1)!

	seq.add_element(ctx1)!
	seq.add_element(ctx2)!

	seq.encode(mut out)!
}

fn HostAddress.decode(src []u8, loc i64) !(HostAddress, i64) {
	seq, n := asn1.Sequence.decode(src, 0)!
	els := seq.elements()!

	// el0 is rawelement of tagged type
	el0 := els[0] as asn1.RawElement
	el1 := els[1] as asn1.RawElement
	// should integer
	expected_inner0, _ := Integer.decode(el0.payload)!
	expected_inner1, _ := asn1.OctetString.decode(el1.payload)!
	return HostAddress{
		addr_type: expected_inner0.int()
		address: expected_inner1
	}, n
}
