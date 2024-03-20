// Copyright (c) 2022, 2023 blackshirt. All rights reserved.
// Use of this source code is governed by a MIT License
// that can be found in the LICENSE file.
module asn1

// IA5String handling routine
// Standard ASCII characters
struct IA5String {
	value string
mut:
	tag Tag = new_tag(.universal, false, int(TagType.ia5string)) or { panic(err) }
}

fn IA5String.from_string(value string) !IA5String {
	if !value.is_ascii() {
		return error('IA5String: contains non-ascii chars')
	}
	return IA5String{
		value: value
	}
}

fn IA5String.from_bytes(b []u8) !IA5String {
	if b.any(it < u8(` `) || it > u8(`~`)) {
		return error('IA5String: bytes contains non-ascii chars')
	}
	return IA5String{
		value: b.bytestr()
	}
}

fn (v IA5String) tag() Tag {
	return v.tag
}

fn (v IA5String) payload(p Params) ![]u8 {
	if !v.value.is_ascii() {
		return error('IA5String: contains non-ascii chars')
	}
	return v.value.bytes()
}

fn (v IA5String) length(p Params) int {
	return v.value.len
}

fn (v IA5String) packed_length(p Params) int {
	mut n := 0

	n += v.tag().packed_length(p)
	len := Length.from_i64(v.value.bytes().len) or { panic(err) }
	n += len.packed_length(p)
	n += v.value.bytes().len

	return n
}

fn (v IA5String) pack_to_asn1(mut dst []u8, p Params) ! {
	if !v.value.is_ascii() {
		return error('IA5String: contains non-ascii char')
	}
	if p.mode != .der && p.mode != .ber {
		return error('IA5String: unsupported mode')
	}

	v.tag().pack_to_asn1(mut dst, p)!
	bytes := v.value.bytes()
	length := Length.from_i64(bytes.len)!
	length.pack_to_asn1(mut dst, p)!
	dst << bytes
}

fn IA5String.unpack_from_asn1(src []u8, loc i64, p Params) !(IA5String, i64) {
	if src.len < 2 {
		return error('IA5String: bad ia5string bytes length')
	}
	if p.mode != .der && p.mode != .ber {
		return error('IA5String: unsupported mode')
	}
	if loc > src.len {
		return error('IA5String: bad position offset')
	}

	tag, pos := Tag.unpack_from_asn1(src, loc, p)!
	// TODO: checks tag for matching type
	if tag.class() != .universal || tag.is_constructed()
		|| tag.tag_number() != int(TagType.ia5string) {
		return error('IA5String: bad tag of universal class type')
	}
	// read the length part from current position pos
	len, idx := Length.unpack_from_asn1(src, pos, p)!
	// read the bytes part from current position idx to the length part
	// TODO: dont trust provided length, make sure to do checking
	if idx > src.len || idx + len > src.len {
		return error('IA5String: truncated input')
	}
	// no bytes
	if len == 0 {
		ret := IA5String{
			tag: tag
		}
		return ret, idx
	}
	bytes := unsafe { src[idx..idx + len] }
	// check for ASCII charset
	if bytes.any(it < u8(` `) || it > u8(`~`)) {
		return error('IA5String: bytes contains non-ascii chars')
	}
	ret := IA5String{
		tag: tag
		value: bytes.bytestr()
	}
	return ret, idx + len
}
