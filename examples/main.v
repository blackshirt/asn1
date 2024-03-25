module main

import asn1

// type KerberosString = GeneralString
struct KerberosString {
	tag   asn1.Tag = asn1.new_tag(.universal, false, int(asn1.TagType.generalstring)) or { panic(err) }
	value string
}

fn valid_kerberos_string(s string) bool {
	if s.is_ascii() {
		return true
	}
	return false
}

fn KerberosString.from_string(s string) !KerberosString {
	if !valid_kerberos_string(s) {
		return error('not valid kerberos string')
	}
	return KerberosString{
		value: s
	}
}

fn KerberosString.from_bytes(b []u8) !KerberosString {
	if !valid_kerberos_string(b.bytestr()) {
		return error('not valid kerberos string')
	}
	return KerberosString{
		value: b.bytestr()
	}
}

fn (k KerberosString) tag() asn1.Tag {
	return k.tag
}

// your validation logic here
fn (k KerberosString) valid() bool {
	if valid_kerberos_string(k.value) {
		return true
	}
	return false
}

fn (k KerberosString) payload(p asn1.Params) ![]u8 {
	return k.value.bytes()
}

fn (k KerberosString) packed_length(p asn1.Params) int {
	return k.value.bytes().len
}

fn (k KerberosString) encode(mut out []u8, p asn1.Params) ! {
	// do your validation check for KerberosString type
	if !k.valid() {
		return error('not valid KerberosString')
	}
	k.tag().encode(mut out, p)!
	bytes := k.value.bytes()
	length := asn1.Length.from_i64(bytes.len)!
	length.encode(mut out, p)!
	out << bytes
}

fn KerberosString.decode(src []u8, loc i64, p asn1.Params) !(KerberosString, i64) {
	raw, next := asn1.RawElement.decode(src, loc, p)!
	if raw.tag().tag_number() != int(asn1.TagType.generalstring) {
		return error('bad tag')
	}
	if raw.payload.len == 0 {
		return KerberosString.from_string('')!, next
	}

	// validates
	ks := KerberosString.from_bytes(raw.payload(p)!)!
	return ks, next
}

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
		ks := item as KerberosString
		seq2.add_element(ks)!
	}
	el1 := asn1.TaggedType.explicit_context(seq2, 1)!

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
	payload := pn.payload(p) or { panic(err) }
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
	for item in pn.name_string {
		ks := item as KerberosString
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
	el0 := tt0.inner_el as asn1.Int64

	tag1 := asn1.new_tag(.universal, true, int(asn1.TagType.sequence))!
	tt1 := re1.as_tagged(.explicit, tag1)!
	el1 := tt1.inner_el as asn1.Sequence

	f0 := el1.elements()![0] as KerberosString

	ret := PrincipalName{
		name_type: el0
		name_string: [f0]
	}
	return ret, pos
}

fn main() {
	// Basically this is a Kerberos PrincipalName data you sent to me
	data := [u8(0x30), 0x15, 0xa0, 0x03, 0x02, 0x01, 0x01, 0xa1, 0x0e, 0x30, 0x0c, 0x1b, 0x0a,
		0x62, 0x6f, 0x62, 0x62, 0x61, 0x2d, 0x66, 0x65, 0x74, 0x74]
	p := PrincipalName{
		name_type: asn1.Int64.from_i64(1)
		name_string: [KerberosString.from_string('bobba-fett')!]
	}
	mut out := []u8{}
	p.encode(mut out)!
	assert out == data // should assert to true
}
