// Copyright (c) 2022, 2023 blackshirt. All rights reserved.
// Use of this source code is governed by a MIT License
// that can be found in the LICENSE file.
module primitive

import asn1

// IA5String handling routine
// Standard ASCII characters
struct IA5String {
	value string
mut:
	tag asn1.Tag = asn1.new_tag(.universal, false, int(asn1.TagType.ia5string)) or { panic(err) }
}

fn IA5String.new(value string) !IA5String {
	if !value.is_ascii() {
		return error('IA5String: contains non-ascii chars')
	}
	return IA5String{
		value: value
	}
}

fn (v IA5String) tag() asn1.Tag {
	return v.tag
}

fn (v IA5String) pack_to_asn1(mut to []u8, mode asn1.EncodingMode, p asn1.Params) ! {
	if !v.value.is_ascii() {
		return error('IA5String: contains non-ascii char')
	}
	match mode {
		.ber, .der {
			v.tag().pack_to_asn1(mut to, mode, p)!
			bytes := v.value.bytes()
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
			if tag.class() != .universal || tag.is_compound()
				|| tag.tag_number() != int(asn1.TagType.ia5string) {
				return error('IA5String: bad tag of universal class type')
			}
			// read the length part from current position pos
			len, idx := asn1.Length.unpack_from_asn1(b, pos, mode, p)!
			// read the bytes part from current position idx to the length part
			// TODO: dont trust provided length, make sure to do checks
			bytes := unsafe { b[idx..idx + len] }
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
		else {
			return error('unsupported mode')
		}
	}
}
