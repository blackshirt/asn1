module main

// EncryptedData   ::= SEQUENCE {
//           etype   [0] Int32 -- EncryptionType --,
//           kvno    [1] UInt32 OPTIONAL,
//           cipher  [2] OCTET STRING -- ciphertext
//   }
// minimal bytes to represent this structure, because etype and cipher should present
// explicit integer : 5 bytes + explicit octet cipher 4 + sequence header 2 = 11
struct EncryptedData {
	tag    asn1.Tag = asn1.new_tag(.universal, true, int(asn1.TagType.sequence)) or { panic(err) }
	etype  int
	kvno   ?u32 = none // OPTIONAL
	cipher asn1.OctetString
}

fn (e EncryptedData) tag() asn1.Tag {
	return e.tag
}

fn (e EncryptedData) length(p asn1.Params) int {
	mut n := 0
	el0 := asn1.TaggedType.explicit_context(asn1.Int64.from_i64(e.etype), 0) or { panic(err) }
	// el1 := asn1.TaggedType.explicit_context( asn1.Int64.from_i64(e.kvno), 1)or { panic(err) }
	el2 := asn1.TaggedType.explicit_context(e.cipher, 2) or { panic(err) }

	n += el0.packed_length(p)
	if e.kvno != none {
		el1 := asn1.TaggedType.explicit_context(asn1.Int64.from_i64(e.kvno), 1) or { panic(err) }
		n += el1.packed_length(p)
	}
	n += el2.packed_length(p)

	return n
}

fn (e EncryptedData) payload(p asn1.Params) ![]u8 {
	mut out := []u8{}
	el0 := asn1.TaggedType.explicit_context(asn1.Int64.from_i64(e.etype), 0)!
	el2 := asn1.TaggedType.explicit_context(e.cipher, 2)!
	el0.encode(mut out, p)!
	if e.kvno != none {
		el1 := asn1.TaggedType.explicit_context(asn1.Int64.from_i64(e.kvno), 1)!
		el1.encode(mut out, p)!
	}
	el2.encode(mut out, p)!

	return out
}

fn (e EncryptedData) encode(mut out []u8, p asn1.Params) ! {
	e.tag().encode(mut out, p)!
	length := asn1.Length.from_i64(e.length(p))!
	length.encode(mut out, p)!
	out << e.payload(p)!
}

fn EncryptedData.decode(src []u8, loc i64, p asn1.Params) !(EncryptedData, i64) {
	if src.len < 11 {
		return error('EncryptedData: bytes underflow')
	}
	tlv, next := asn1.Tlv.read(src, loc, p)!
	if tlv.tag.class() != .universal && !tlv.tag.is_constructed()
		&& tlv.tag.tag_number() != int(asn1.TagType.sequence) {
		return error('EncryptedData: check tag failed')
	}

	if tlv.length() == 0 {
		return error('EncryptedData: length should != 0')
	}

	// sequence elements contents
	els := asn1.ElementList.from_bytes(tlv.content())!
	if els.len < 2 {
		return error('ElementList < 2')
	}

	// check if optional element is present
	kvno_present := if els.len == 3 { true } else { false }
	els0 := els[0] as asn1.TaggedType // would panic if not hold asn1.TaggedType
	els1 := if kvno_present { els[1] as asn1.TaggedType } else { none }
	els2 := els[2] as asn1.OctetString
	// check the result
	ed := EncryptedData{
		etype: (els0.inner_el as asn1.Int64).value() // etype is int
		kvno: (els1 as asn1.Int64).value() //
		cipher: els2
	}
	return ed, idx + length
}
