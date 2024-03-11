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
	tag asn1.Tag = asn1.new_tag(.universal, false, int(asn1.TagType.visiblestring))!
}

fn VisibleString.new(s string) !VisibleString {
	if contains_ctrl_chars(s.bytes()) {
		return error('VisibleString: contains control chars')
	}
	return VisibleString{
		value: s
	}
}

fn VisibleString.new_from_bytes(b []u8) !VisibleString {
	if contains_ctrl_chars(b) {
		return error('VisibleString: contains control chars')
	}
	return VisibleString{
		value: b.bytestr()
	}
}

fn (v VisibleString) tag() asn1.Tag {
	return v.tag
}

fn (v VisibleString) pack_to_asn1(mut to []u8, mode asn1.EncodingMode, p asn1.Params) ! {
	// recheck
	if contains_ctrl_chars(v.value.bytes()) {
		return error('VisibleString: contains control chars')
	}
	match mode {
		.ber, .der {
			v.tag().pack_to_asn1(mut to, mode, p)!
			length := asn1.Length.from_i64(v.value.bytes().len)!
			length.pack_to_asn1(mut to, mode, p)!
			to << v.value.bytes()
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
				return error('VisibleString: bad tag of universal class type')
			}
			len, idx := asn1.Length.unpack_from_asn1(b, pos, mode, p)!
			// TODO: check the length, its safe to access bytes
			bytes := unsafe { b[idx..idx + len] }

			vs := VisibleString.new_from_bytes(bytes)!
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

fn contains_ctrl_chars(bytes []u8) bool {
	return bytes.any(is_ctrl_char(it))
}

/*
pub fn new_visiblestring(s string) !Encoder {
	if !is_visiblestring(s.bytes()) {
		return error('bad visible char')
	}
	return VisibleString(s)
}

pub fn (vs VisibleString) length() int {
	return vs.len
}

pub fn (vs VisibleString) size() int {
	mut size := 0
	tag := vs.tag()
	t := calc_tag_length(tag)
	size += t

	l := calc_length_of_length(vs.length())
	size += int(l)

	size += vs.length()

	return size
}

pub fn (vs VisibleString) encode() ![]u8 {
	return serialize_visiblestring(vs)
}


fn is_visiblestring(src []u8) bool {
	for c in src {
		if is_ctrl_char(c) {
			return false
		}
	}
	return true
}

fn serialize_visiblestring(s string) ![]u8 {
	p := s.bytes()
	if !is_visiblestring(p) {
		return error('contains invalid (control) char')
	}

	t := new_tag(.universal, false, int(TagType.visiblestring))
	mut out := []u8{}

	serialize_tag(mut out, t)
	serialize_length(mut out, p.len)
	out << p
	return out
}

fn decode_visiblestring(src []u8) !(Tag, string) {
	if src.len < 2 {
		return error('decode numeric: bad payload len')
	}
	tag, pos := read_tag(src, 0)!
	if tag.number != int(TagType.visiblestring) {
		return error('bad tag')
	}
	if pos > src.len {
		return error('truncated input')
	}

	// mut length := 0
	length, next := decode_length(src, pos)!

	if next > src.len {
		return error('truncated input')
	}
	out := src[next..next + length]

	if !is_visiblestring(out) {
		return error('invalid UTF-8 string')
	}

	return tag, out.bytestr()
}
*/
