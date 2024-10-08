// Copyright (c) 2022, 2023 blackshirt. All rights reserved.
// Use of this source code is governed by a MIT License
// that can be found in the LICENSE file.
module asn1

// IA5String handling routine
// Standard ASCII characters
pub struct IA5String {
	tag   Tag = Tag{.universal, false, int(TagType.ia5string)}
	value string
}

// from_string creates IA5String from string s
pub fn IA5String.from_string(s string, p Params) !IA5String {
	if !valid_ia5string(s) {
		return error('IA5String: contains non-ascii chars')
	}
	return IA5String{
		value: s
	}
}

// IA5String.from_raw_element transforms RawElement in `re` into IA5String
pub fn IA5String.from_raw_element(re RawElement, p Params) !IA5String {
	// check validity of the RawElement tag
	if re.tag.tag_class() != .universal {
		return error('RawElement class is not .universal, but : ${re.tag.tag_class()}')
	}
	if p.mode == .der {
		if re.tag.is_constructed() {
			return error('RawElement constructed is not allowed in .der')
		}
	}
	if re.tag.number.universal_tag_type()! != .ia5string {
		return error('RawElement tag does not hold .ia5string type')
	}
	bytes := re.payload(p)!
	bs := IA5String.from_bytes(bytes, p)!

	return bs
}

// from_bytes creates a new IA5String from bytes b
pub fn IA5String.from_bytes(b []u8, p Params) !IA5String {
	if b.any(it < u8(` `) || it > u8(`~`)) {
		return error('IA5String: bytes contains non-ascii chars')
	}
	return IA5String{
		value: b.bytestr()
	}
}

pub fn (v IA5String) tag() Tag {
	return v.tag
}

pub fn (v IA5String) value() string {
	return v.value
}

pub fn (v IA5String) payload(p Params) ![]u8 {
	if !v.value.is_ascii() {
		return error('IA5String: contains non-ascii chars')
	}
	return v.value.bytes()
}

pub fn (v IA5String) length(p Params) !int {
	return v.value.len
}

pub fn (v IA5String) packed_length(p Params) !int {
	mut n := 0

	n += v.tag.packed_length(p)!
	len := Length.from_i64(v.value.bytes().len)!
	n += len.packed_length(p)!
	n += v.value.bytes().len

	return n
}

pub fn (v IA5String) encode(mut dst []u8, p Params) ! {
	if !v.value.is_ascii() {
		return error('IA5String: contains non-ascii char')
	}
	if p.mode != .der && p.mode != .ber {
		return error('IA5String: unsupported mode')
	}

	v.tag.encode(mut dst, p)!
	bytes := v.value.bytes()
	length := Length.from_i64(bytes.len)!
	length.encode(mut dst, p)!
	dst << bytes
}

pub fn IA5String.decode(src []u8, loc i64, p Params) !(IA5String, i64) {
	raw, next := RawElement.decode(src, loc, p)!
	// TODO: checks tag for matching type
	if raw.tag.tag_class() != .universal || raw.tag.is_constructed()
		|| raw.tag.tag_number() != int(TagType.ia5string) {
		return error('IA5String: bad tag of universal class type')
	}
	// no bytes
	if raw.payload.len == 0 {
		return IA5String{}, next
	}
	ret := IA5String.from_bytes(raw.payload, p)!

	return ret, next
}

// Utility function
fn valid_ia5string(s string) bool {
	return s.is_ascii()
}
