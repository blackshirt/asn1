module main

// PrincipalName   ::= SEQUENCE {
//    name-type       [0] Int32,
//    name-string     [1] SEQUENCE OF KerberosString
// }
struct PrincipalName {
	tag         asn1.Tag = asn1.new_tag(.universal, true, int(asn1.TagType.sequence)) or { panic(err) }
	name_type   asn1.Int64
	name_string []KerberosString
}

fn (pn PrincipalName) tag() asn1.Tag {
	return pn.tag
}

fn (pn PrincipalName) payload(p asn1.Params) ![]u8 {
	el0 := asn1.TaggedType.explicit_context(pn.name_type, 0)!
	// second element is SEQUENCEOF
	mut seq2 := asn1.Sequence.new(true)!
	for item in pn.name_string {
		ks := KerberosString.from_string(item)!
		seq2.add_element(ks)!
	}
	el1 := asn1.TaggedType.explicit_context(seq2, 1)

	mut out := []u8{}
	el0.encode(mut out, p)!
	el1.encode(mut out, p)!
	return out
}

fn (pn PrincipalName) length(p asn1.Params) int {
	mut n := 0
	payload := pn.payload(p) or { panic(err) }
	n += payload.len
	return n
}

fn (pn PrincipalName) packed_length(p asn1.Params) int {
	mut n := 0

	n += pn.tag().packed_length(p)
	payload := pn.payload(p)!
	len := asn1.Length.from_i64(payload.len) or { panic(err) }
	n += len.packed_length(p)
	n += payload.len

	return n
}

fn (pn PrincipalName) encode(mut dst []u8, p asn1.Params) ! {
	mut seq1 := asn1.Sequence.new(false)!
	// explicit context of integer content
	exp1 := asn1.TaggedType.explicit_context(pn.name_type, 0)!
	seq1.add_element(exp1)!

	// second element is SEQUENCEOF
	mut seq2 := asn1.Sequence.new(true)!
	for ks in pn.name_string {
		seq2.add_element(ks)!
	}
	exp2 := asn1.TaggedType.explicit_context(seq2, 1)!
	seq1.add_element(exp2)!

	seq1.encode(mut dst, p)!
}

fn PrincipalName.decode(src []u8, loc i64, p asn1.Params) !(PrincipalName, i64) {
	// PrincipalName is sequence
	seq, pos := asn1.Sequence.decode(src, loc, p)!
	// when src.len is exact length of PrincipalName data, maybe not one
	assert pos == src.len
	assert seq.elements()!.len == 2
	// all sequence elements when parsed, if has not .universal class
	// is parsed as asn1.RawElement
	els := seq.elements()!

	// first element is exlicit context of integer
	re0 := els[0] as asn1.RawElement
	re1 := els[1] as asn1.RawElement

	tag0 := asn1.new_tag(.universal, false, 2)!
	tt0 := re0.as_tagged(.explicit, tag0)!
	el0 := tt0 as asn1.Int64

	tag1 := asn1.new_tag(.universal, true, int(asn1.TagType.sequence))!
	tt1 := re1.as_tagged(.explicit, tag1)!
	el1 := tt1 as Sequence

	f0 := el1.elements()![0] as KerberosString

	ret := PrincipalName{
		name_type: el0
		name_string: [f0]
	}
	return ret, pos
}
