module main

// PA-DATA         ::= SEQUENCE {
//     -- NOTE: first tag is [1], not [0]
//     padata-type     [1] Int32,
//     padata-value    [2] OCTET STRING -- might be encoded AP-REQ
// }

struct PaData {
	pd_type  int
	pd_value asn1.OctetString
}

// validate
fn (p PaData) valid() bool {
	return true
}

fn (p PaData) tag() asn1.Tag {
	return p.tag
}

fn (p PaData) packed_length() int {
	mut n := 0

	n += p.tag().packed_length()

	return n
}

fn (p PaData) pack(mut out []u8) ! {
	if !p.valid() {
		return error('not valid')
	}
	tt0 := asn1.TaggedType.explicit_context(p.pd_type, 1)!
	tt1 := asn1.TaggedType.explicit_context(p.pd_value, 2)!
	el0 := tt0.to_element()!
	el1 := tt1.to_element()!

	mut els := []Element{}
	mut seq := asn1.Sequence.new(new_tag(.universal, true, int(asn1.TagType.sequence))!,
		false, els)!

	seq.add_element(el0)!
	seq.add_element(el1)!

	mut pa_length := 0
	pa_length += el0.packed_length()
	pa_length += el1.packed_length()
}

fn PaData.unpack(src []u8) !PaData {
	if src.len < 2 {
		return error('src underflow')
	}
	seq, n := asn1.Sequence.decode(src, 0)!
	assert seq.elements.len == 2
}
