// Copyright (c) 2022, 2023 blackshirt. All rights reserved.
// Use of this source code is governed by a MIT License
// that can be found in the LICENSE file.
module primitive

import asn1

// OCTETSTRING
// The ASN.1 OCTET STRING type contains arbitrary strings of octets.
// This type is very similar to BIT STRING, except that all values must be an integral number of eight bits.
// You can use constraints to specify a maximum length for an OCTET STRING type.
struct OctetString {
	value string
mut:
	tag asn1.Tag = asn1.new_tag(.universal, false, int(asn1.TagType.octetstring)) or { panic(err) }
}

// new_octetstring creates new octet string
fn OctetString.from_string(s string) OctetString {
	return OctetString{
		value: s
	}
}

fn OctetString.from_bytes(b []u8) OctetString {
	return OctetString.from_string(b.bytestr())
}

fn (os OctetString) tag() asn1.Tag {
	return os.tag
}

fn (os OctetString) pack_to_asn1(mut to []u8, mode asn1.EncodingMode, p asn1.Params) ! {
	match mode {
		.ber, .der {
			os.tag().pack_to_asn1(mut to, mode, p)!
			length := asn1.Length.from_i64(os.value.bytes().len)!
			length.pack_to_asn1(mut to, mode, p)!
			to << os.value.bytes()
		}
		else {
			return error('unsupported')
		}
	}
}

fn OctetString.unpack_from_asn1(b []u8, loc i64, mode asn1.EncodingMode, p asn1.Params) !(OctetString, i64) {
	if b.len < 2 {
		return error('OctetString: bad b.len underflow')
	}
	match mode {
		.ber, .der {
			tag, pos := asn1.Tag.unpack_from_asn1(b, loc, mode, p)!
			if tag.class() != .universal || tag.is_compound()
				|| tag.tag_number() != int(asn1.TagType.octetstring) {
				return error('OctetString: bad tag of universal class type')
			}
			len, idx := asn1.Length.unpack_from_asn1(b, pos, mode, p)!
			// TODO: check the length, its safe to access bytes
			bytes := unsafe { b[idx..idx + len] }

			os := OctetString.from_bytes(bytes)
			return os, idx + len
		}
		else {
			return error('Unsupported mode')
		}
	}
}
