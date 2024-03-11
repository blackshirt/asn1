// Copyright (c) 2022, 2023 blackshirt. All rights reserved.
// Use of this source code is governed by a MIT License
// that can be found in the LICENSE file.
module primitive

import asn1

// IA5String handling routine
// Standard ASCII characters
struct IA5String {
mut:
	tag asn1.Tag = asn1.new_tag(.universal, false, 22)!
	s   string
}

fn IA5String.new(s string) !IA5String {
	if !s.is_ascii() {
		return error('IA5String: contains non-ascii chars')
	}
	return IA5String{
		s: s
	}
}

fn (v IA5String) tag() asn1.Tag {
	return v.tag
}

fn (v IA5String) pack_to_asn1(mut to []u8, mode asn1.EncodingMode, p asn1.Params) ! {
	if !v.s.is_ascii() {
		return error('IA5String: contains non-ascii char')
	}
	match mode {
		.ber, .der {
			v.tag().pack_to_asn1(mut to, mode, p)!
			bytes := v.s.bytes()
			length := asn1.Length.from_i64(bytes.len)!
			length.pack_to_asn1(mut to, mode, p)!
			to << bytes
		}
		else {
			return error('unsupported mode')
		}
	}
}

fn IA5String.unpack_from_asn1(b []u8, loc i64, mode asn1.EncodingMode, p asn1.Params) !(IA5String, i64) {
	if b.len < 2 {
		return error('IA5String: bad ia5string bytes length')
	}
	match mode {
		.ber, .der {
			tag, pos := asn1.Tag.unpack_from_asn1(b, loc, mode, p)!
			// TODO: checks tag for matching type
			if tag.class() != .universal || tag.is_compound() || tag.tag_number() != 22 {
				return error('IA5String: bad tag of universal class type')
			}
			// read the length part from current position pos
			len, idx := asn1.Length.unpack_from_asn1(b, pos, mode, p)!
			// read the bytes part from current position idx to the length part
			// TODO: dont trust provided length, make sure to do checks
			bytes := unsafe { b[idx..idx + len] }
			// check for ASCII charset
			if bytes.any(it < u8(` `) || it > u8(`~`)) {
				return error('bytes contains non-ascii chars')
			}
			ret := IA5String{
				tag: tag
				s: bytes.bytestr()
			}
			return ret, idx + len
		}
		else {
			return error('unsupported mode')
		}
	}
}

/*
fn decode_ia5string(src []u8) !(Tag, string) {
	if src.len < 2 {
		return error('decode numeric: bad payload len')
	}
	tag, pos := read_tag(src, 0)!
	if tag.number != int(TagType.ia5string) {
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
	out := read_bytes(src, next, length)!

	if !is_ia5string(out.bytestr()) {
		return error('contains invalid char')
	}
	return tag, out.bytestr()
}
*/
