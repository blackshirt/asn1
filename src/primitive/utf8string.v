// Copyright (c) 2022, 2023 blackshirt. All rights reserved.
// Use of this source code is governed by a MIT License
// that can be found in the LICENSE file.
module primitive

import encoding.utf8
import asn1

// UTF8String
// UTF8 unicode charset
//
struct UTF8String {
	value string
mut:
	tag asn1.Tag = asn1.new_tag(.universal, false, int(asn1.TagType.utf8string)) or { panic(err) }
}

fn UTF8String.from_string(s string) !UTF8String {
	if !utf8.validate_str(s) {
		return error('UTF8String: invalid UTF-8 string')
	}
	return UTF8String{
		value: s
	}
}

fn UTF8String.from_bytes(b []u8) !UTF8String {
	if !utf8.validate_str(b.bytestr()) {
		return error('UTF8String: invalid UTF-8 string')
	}
	return UTF8String{
		value: b.bytestr()
	}
}

fn (us UTF8String) tag() asn1.Tag {
	return us.tag
}

fn (us UTF8String) pack_to_asn1(mut to []u8, mode asn1.EncodingMode, p asn1.Params) ! {
	// recheck
	if !utf8.validate_str(us.value) {
		return error('UTF8String: invalid UTF-8 string')
	}
	match mode {
		.ber, .der {
			us.tag().pack_to_asn1(mut to, mode, p)!
			length := asn1.Length.from_i64(us.value.bytes().len)!
			length.pack_to_asn1(mut to, mode, p)!
			to << us.value.bytes()
		}
		else {
			return error('unsupported')
		}
	}
}

fn UTF8String.unpack_from_asn1(b []u8, loc i64, mode asn1.EncodingMode, p asn1.Params) !(UTF8String, i64) {
	if b.len < 2 {
		return error('UTF8String: b.len underflow')
	}
	match mode {
		.ber, .der {
			tag, pos := asn1.Tag.unpack_from_asn1(b, loc, mode, p)!
			if tag.class() != .universal || tag.is_compound()
				|| tag.tag_number() != int(asn1.TagType.utf8string) {
				return error('UTF8String: bad tag of universal class type')
			}
			len, idx := asn1.Length.unpack_from_asn1(b, pos, mode, p)!
			// TODO: check the length, its safe to access bytes
			bytes := unsafe { b[idx..idx + len] }

			us := UTF8String.from_bytes(bytes)!
			return us, idx + len
		}
		else {
			return error('Unsupported mode')
		}
	}
}
