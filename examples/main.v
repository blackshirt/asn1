module main

import asn1

// type KerberosString = GeneralString
struct KerberosString {
	value string
}

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

fn (k KerberosString) payload() ![]u8 {
	if !valid_kerberos_string(k.value) {
		return error('contains invalid string')
	}
	return k.value.bytes()
}

// PrincipalName   ::= SEQUENCE {
//    name-type       [0] Int32,
//    name-string     [1] SEQUENCE OF KerberosString
// }
struct PrincipalName {
	name_type   asn1.Integer                    @[context_specific: 0; inner: 'universal,false,2'; mode: explicit] // integer tag = (universal, false, 2)
	name_string asn1.SequenceOf[KerberosString] @[context_specific: 1; inner: 'universal,true,17'; mode: explicit] // set tag = (universal, true, 17)
}

fn (pn PrincipalName) tag() asn1.Tag {
	return asn1.default_sequence_tag
}

fn (pn PrincipalName) payload() ![]u8 {
	kd := KeyDefault{}
	payload := asn1.make_payload[PrincipalName](pn, kd)!
	return payload
}

fn PrincipalName.decode(src []u8) !PrincipalName {
	return error('not implemented')
}

fn main() {
	// Basically this is a Kerberos PrincipalName data
	data := [u8(0x30), 0x15, 0xa0, 0x03, 0x02, 0x01, 0x01, 0xa1, 0x0e, 0x30, 0x0c, 0x1b, 0x0a,
		0x62, 0x6f, 0x62, 0x62, 0x61, 0x2d, 0x66, 0x65, 0x74, 0x74]
	p := PrincipalName{
		name_type:   asn1.Integer.from_i64(1)
		name_string: [KerberosString.from_string('bobba-fett')!]
	}
	mut out := []u8{}
	p.encode(mut out)!

	back, n := PrincipalName.decode(data, 0)!
	dump(n == data.len)
	dump(back == p)
	dump(out == data) // should assert to true
}
