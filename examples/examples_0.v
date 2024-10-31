module main

import asn1

type KerberosString = asn1.GeneralString

fn (k KerberosString) tag() asn1.Tag {
	return asn1.default_generalstring_tag
}

fn valid_kerberos_string(s string) bool {
	return s.is_ascii()
}

fn KerberosString.new(s string) !KerberosString {
	if !valid_kerberos_string(s) {
		return error('not valid kerberos string')
	}
	return KerberosString(asn1.GeneralString.new(s))
}

fn KerberosString.from_bytes(b []u8) !KerberosString {
	if !valid_kerberos_string(b.bytestr()) {
		return error('not valid kerberos string')
	}
	return KerberosString(asn1.GeneralString.new(b.bytestr()))
}

fn (k KerberosString) payload() ![]u8 {
	if !valid_kerberos_string(k.value) {
		return error('contains invalid string')
	}

	return k.payload()!
}

// PrincipalName   ::= SEQUENCE {
//    name-type       [0] Int32,
//    name-string     [1] SEQUENCE OF KerberosString
// }
struct PrincipalName {
	name_type   asn1.Integer                    @[context_specific: 0; explicit; inner: 2]  // integer tag = (universal, false, 2)
	name_string asn1.SequenceOf[KerberosString] @[context_specific: 1; explicit; inner: 16] // sequence tag = (universal, true, 16)
}

fn (pn PrincipalName) tag() asn1.Tag {
	return asn1.default_sequence_tag
}

fn (pn PrincipalName) payload() ![]u8 {
	kd := asn1.KeyDefault(map[string]asn1.Element{})
	payload := asn1.make_payload[PrincipalName](pn, kd)!
	return payload
}

fn PrincipalName.decode(bytes []u8) !PrincipalName {
	// decode should produces Sequence type
	elem := asn1.decode(bytes)!
	assert elem.tag().equal(asn1.default_sequence_tag)

	// cast it into Sequence type and get the fields
	seq := elem.into_object[asn1.Sequence]()!
	fields := seq.fields()

	// every fields of the sequence is raw of wrapped element, so we should unwrap it with
	// the same options used to wrap in encode step, and turn to the real underlying object.
	el_name_type := fields[0].unwrap_with_options('context_specific: 0; explicit; inner: 2')!
	name_type := el_name_type.into_object[asn1.Integer]()!

	// tag 16 is sequence tag, its decoded into Sequence type
	el_name_string := fields[1].unwrap_with_options('context_specific: 1; explicit; inner: 16')!
	el_seq := el_name_string.into_object[asn1.Sequence]()!
	mut a := []KerberosString{}
	for item in el_seq.fields() {
		gst := item.into_object[asn1.GeneralString]()!
		obj := KerberosString(gst)
		a << obj
	}

	name_string_list := asn1.SequenceOf.from_list[KerberosString](a)!

	return PrincipalName{
		name_type:   name_type
		name_string: name_string_list
	}
}

fn main() {
	// Basically this is a Kerberos PrincipalName data
	data := [u8(0x30), 0x15, 0xa0, 0x03, 0x02, 0x01, 0x01, 0xa1, 0x0e, 0x30, 0x0c, 0x1b, 0x0a,
		0x62, 0x6f, 0x62, 0x62, 0x61, 0x2d, 0x66, 0x65, 0x74, 0x74]
	els := [KerberosString.new('bobba-fett')!]

	pn := PrincipalName{
		name_type:   asn1.Integer.from_i64(1)
		name_string: asn1.SequenceOf.from_list[KerberosString](els)!
	}
	$for field in pn.fields {
		dump(field)
		// dump(field.typ is asn1.Element)
		// only serialiaze field that implement interfaces
		$if field.typ is asn1.Element {
			// dump(field)
		}
	}
	dump(pn.payload()!)
	out1 := asn1.encode(pn)!
	//dump(out1.hex())
	back := PrincipalName.decode(data)!
	//dump(back)
	//dump(back == pn)
	//dump(out1.hex()) // should assert to true
	//dump(data.hex())
}
