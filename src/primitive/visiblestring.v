// Copyright (c) 2022, 2023 blackshirt. All rights reserved.
// Use of this source code is governed by a MIT License
// that can be found in the LICENSE file.
module primitive

import asn1

// VisibleString
// The ASN.1 VisibleString type supports a subset of ASCII characters that does not include control characters.
//
struct VisibleString {
	value string
mut:
	tag asn1.Tag = asn1.new_tag(.universal, false, int(asn1.TagType.visiblestring)) or { panic(err) }
}

fn VisibleString.from_string(s string) !VisibleString {
	if contains_ctrl_chars(s.bytes()) {
		return error('VisibleString: contains control chars')
	}
	return VisibleString{
		value: s
	}
}

fn VisibleString.from_bytes(b []u8) !VisibleString {
	if contains_ctrl_chars(b) {
		return error('VisibleString: contains control chars')
	}
	return VisibleString{
		value: b.bytestr()
	}
}

fn (vs VisibleString) tag() asn1.Tag {
	return vs.tag
}

fn (vs VisibleString) pack_to_asn1(mut to []u8, mode asn1.EncodingMode, p asn1.Params) ! {
	match mode {
		.ber, .der {
			vs.tag().pack_to_asn1(mut to, mode, p)!
			length := asn1.Length.from_i64(vs.value.bytes().len)!
			length.pack_to_asn1(mut to, mode, p)!
			to << vs.value.bytes()
		}
		else {
			return error('unsupported')
		}
	}
}

fn VisibleString.unpack_from_asn1(b []u8, loc i64, mode asn1.EncodingMode, p asn1.Params) !(VisibleString, i64) {
	if b.len < 2 {
		return error('VisibleString: bad b.len underflow')
	}
	match mode {
		.ber, .der {
			tag, pos := asn1.Tag.unpack_from_asn1(b, loc, mode, p)!
			if tag.class() != .universal || tag.is_compound()
				|| tag.tag_number() != int(asn1.TagType.visiblestring) {
				return error('VisibleString: tag check failed')
			}
			len, idx := asn1.Length.unpack_from_asn1(b, pos, mode, p)!
			// TODO: check the length, its safe to access bytes
			bytes := unsafe { b[idx..idx + len] }

			vs := VisibleString.from_bytes(bytes)!
			return vs, idx + len
		}
		else {
			return error('Unsupported mode')
		}
	}
}

// Utility function

fn is_ctrl_char(c u8) bool {
	return (c >= 0 && c <= 0x1f) || c == 0x7f
}

fn contains_ctrl_chars(b []u8) bool {
	return b.any(is_ctrl_char(it))
}
