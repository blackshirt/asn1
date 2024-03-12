// Copyright (c) 2022, 2023 blackshirt. All rights reserved.
// Use of this source code is governed by a MIT License
// that can be found in the LICENSE file.
module primitive

import asn1

// BITSTRING
//
struct BitString {
	data []u8
	pad  u8
mut:
	tag asn1.Tag = asn1.new_tag(.universal, false, int(asn1.TagType.bitstring))!
}

fn (b BitString) tag() asn1.Tag {
	return b.tag
}

fn BitString.from_string(s string) !BitString {
	return BitString.from_bytes(s.bytes())
}

fn BitString.from_bytes(src []u8) !BitString {
	return BitString.new_with_pad(src, u8(0x00))
}

fn BitString.new_with_pad(src []u8, pad u8) !BitString {
	if pad > 7 || (src.len == 0 && pad != 0) {
		return error('BitString: bad pad bits or zero length')
	}
	if pad > 0 && (src[src.len - 1]) & ((1 << pad) - 1) != 0 {
		return error('BitString: bad args')
	}
	return BitString{
		data: src
		pad: pad
	}
}

fn (bs BitString) bytes_len() int {
	return bs.data.len + 1
}

fn (bs BitString) pack_to_asn1(mut to []u8, mode asn1.EncodingMode, p asn1.Params) ! {
	match mode {
		.ber, .der {
			bs.tag().pack_to_asn1(mut to, mode, p)!
			length := asn1.Length.from_i64(bs.bytes_len())!
			length.pack_to_asn1(mut to, mode, p)!

			// write pad bit and data
			to << bs.pad
			to << bs.data
		}
		else {
			return error('Unsupported mode')
		}
	}
}

fn BitString.unpack_from_asn1(b []u8, loc i64, mode asn1.EncodingMode, p asn1.Params) !(BitString, i64) {
	if b.len < 2 {
		return error('BitString: b.len underflow')
	}
	match mode {
		.ber, .der {
			tag, pos := asn1.Tag.unpack_from_asn1(b, loc, mode, p)!
			if tag.class() != .universal || tag.is_compound()
				|| tag.tag_number() != int(asn1.TagType.bitstring) {
				return error('BitString: bad tag check')
			}
			len, idx := asn1.Length.unpack_from_asn1(b, pos, mode, p)!
			if len == 0 {
				return error('BitString: zero length bit string')
			}
			// todo: check length
			bytes := unsafe { b[idx..idx + len] }

			bs := BitString.new_with_pad(bytes[1..], bytes[0])!
			return bs, idx + len
		}
		else {
			return error('Unsupported mode')
		}
	}
}
