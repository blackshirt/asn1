module main

// KerberosFlags   ::= BIT STRING (SIZE (32..MAX))
//                      -- minimum number of bits shall be sent,
//                      -- but no fewer than 32
const min_kerberosflags_size = 32

struct KerberosFlags {
	tag   asn1.Tag = asn1.new_tag(.universal, false, int(asn1.TagType.bitstring)) or { panic(err) }
	value asn1.BitString
}

fn KerberosFlags.new(value asn1.BitString) !KerberosFlags {
	return KerberosFlags{
		value: value
	}
}

fn (kf KerberosFlags) tag() asn1.Tag {
	return kf.tag
}

fn (kf KerberosFlags) payload(p asn1.Params) ![]u8 {
	return kf.value.payload(p)
}

fn (kf KerberosFlags) length(p asn1.Params) int {
	return kf.value.length(p)
}

fn (kf KerberosFlags) packed_length(p asn1.Params) int {
	return kf.value.packed_length(p)
}

fn (kf KerberosFlags) encode(mut out []u8, p asn1.Params) ! {
	kf.value.encode(mut out, p)!
}

fn KerberosFlags.decode(src []u8, loc i64, p asn1.Params) !(KerberosFlags, i64) {
	b, n := asn1.BitString.decode(src, loc, p)!
	return KerberosFlags.new(b), n
}
