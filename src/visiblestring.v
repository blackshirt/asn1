// Copyright (c) 2022, 2023 blackshirt. All rights reserved.
// Use of this source code is governed by a MIT License
// that can be found in the LICENSE file.
module asn1

// VisibleString
// The ASN.1 VisibleString type supports a subset of ASCII characters that does not include control characters.
//
pub struct VisibleString {
	value string
mut:
	tag Tag = new_tag(.universal, false, int(TagType.visiblestring)) or { panic(err) }
}

pub fn VisibleString.from_string(s string) !VisibleString {
	if contains_ctrl_chars(s.bytes()) {
		return error('VisibleString: contains control chars')
	}
	return VisibleString{
		value: s
	}
}

pub fn VisibleString.from_bytes(src []u8) !VisibleString {
	if contains_ctrl_chars(src) {
		return error('VisibleString: contains control chars')
	}
	return VisibleString{
		value: src.bytestr()
	}
}

pub fn (vs VisibleString) tag() Tag {
	return vs.tag
}

pub fn (vs VisibleString) payload(p Params) ![]u8 {
	if contains_ctrl_chars(vs.value.bytes()) {
		return error('VisibleString: contains control chars')
	}
	return vs.value.bytes()
}

pub fn (vs VisibleString) length(p Params) int {
	return vs.value.len
}

pub fn (vs VisibleString) packed_length(p Params) int {
	mut n := 0
	n += vs.tag().packed_length(p)
	len := Length.from_i64(vs.length(p)) or { panic(err) }
	n += len.packed_length(p)
	n += vs.length(p)

	return n
}

pub fn (vs VisibleString) pack_to_asn1(mut dst []u8, p Params) ! {
	// recheck
	if contains_ctrl_chars(vs.value.bytes()) {
		return error('VisibleString: contains control chars')
	}
	if p.mode != .der && p.mode != .ber {
		return error('Integer: unsupported mode')
	}
	vs.tag().pack_to_asn1(mut dst, p)!
	length := Length.from_i64(vs.value.bytes().len)!
	length.pack_to_asn1(mut dst, p)!
	dst << vs.value.bytes()
}

pub fn VisibleString.unpack_from_asn1(src []u8, loc i64, p Params) !(VisibleString, i64) {
	if src.len < 2 {
		return error('VisibleString: bad src.len underflow')
	}
	if p.mode != .der && p.mode != .ber {
		return error('VisibleString: unsupported mode')
	}
	if loc > src.len {
		return error('VisibleString: bad position offset')
	}

	// unpacking in DER mode
	// get the tag
	tag, pos := Tag.unpack_from_asn1(src, loc, p)!
	if tag.class() != .universal || tag.is_constructed()
		|| tag.tag_number() != int(TagType.visiblestring) {
		return error('VisibleString: tag check failed')
	}
	// get the Length
	len, idx := Length.unpack_from_asn1(src, pos, p)!
	// no bytes
	if len == 0 {
		ret := VisibleString{
			tag: tag
		}
		return ret, idx
	}
	if idx > src.len || idx + len > src.len {
		return error('VisibleString: truncated input')
	}
	// TODO: check the length, its safe to access bytes
	bytes := unsafe { src[idx..idx + len] }

	vs := VisibleString.from_bytes(bytes)!
	return vs, idx + len
}

// Utility function
//
fn is_ctrl_char(c u8) bool {
	return (c >= 0 && c <= 0x1f) || c == 0x7f
}

fn contains_ctrl_chars(src []u8) bool {
	return src.any(is_ctrl_char(it))
}
