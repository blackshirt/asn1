module main

// PA-DATA         ::= SEQUENCE {
//     -- NOTE: first tag is [1], not [0]
//     padata-type     [1] Int32,
//     padata-value    [2] OCTET STRING -- might be encoded AP-REQ
// }

struct PaData {
	tag		 asn1.Tag = asn1.new_tag(.universal, true, int(asn1.TagType.sequence)) or { panic(err) }
	pd_type  asn1.Int64 // we use Int64
	pd_value asn1.OctetString
}

// validate
fn (p PaData) valid() bool {
	return true
}

fn (p PaData) tag() asn1.Tag {
	return p.tag
}

fn (p PaData) payload(p asn1.Params) ![]u8 {
	el0 := asn1.TaggedType.explicit_context(p.pd_type, 1)!
	el1 := asn1.TaggedType.explicit_context(p.pd_value, 2)!

	mut out := []u8{}
	el0.encode(mut out, p)!
	el1.encode(mut out, p)!

	return out 
}

fn (p PaData) packed_length(p asn1.Params) int {
	mut n := 0

	n += p.tag().packed_length()
	payload := p.payload(p) or { panic(err) }
	len := asn1.Length.from_i64(payload.len) or { panic(err) }
	n += len.packed_length(p)
	n += payload.len 

	return n
}

fn (p PaData) encode(mut out []u8, p asn1.Params) ! {
	if !p.valid() {
		return error('not valid')
	}
	el0 := asn1.TaggedType.explicit_context(p.pd_type, 1)!
	el1 := asn1.TaggedType.explicit_context(p.pd_value, 2)!
	
	mut seq := asn1.Sequence.new(false)!
	seq.add_element(el0)!
	seq.add_element(el1)!

	mut out := []u8{}
	seq.encode(mut out, p)!
}

fn PaData.decode(src []u8, loc i64, p asn1.Params) !(PaData, i64) {
	if src.len < 2 {
		return error('src underflow')
	}
	seq, n := asn1.Sequence.decode(src, 0, p)!
	assert seq.elements.len == 2
	
	els := seq.elements()!
	els0 := els[0] as asn1.Int64
	els1 := els[1] as asn1.OctetString

	pa := PaData{
		pd_type: els0 
		pd_value: els1 
	}
	return pa, n 
}
