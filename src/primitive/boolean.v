// Copyright (c) 2022, 2023 blackshirt. All rights reserved.
// Use of this source code is governed by a MIT License
// that can be found in the LICENSE file.
module primitive

import asn1

// ASN.1 BOOLEAN
//
// A Boolean value can take true or false.
// ASN.1 DER encoding restricts encoding of boolean true value to 0xff
// and otherwise, encodes to zero (0x00) for false value.
// The encoding of a boolean value shall be primitive. The contents octets shall consist of a single octet.
struct Boolean {
	value bool
mut:
	tag asn1.Tag = asn1.new_tag(.universal, false, int(asn1.TagType.boolean))!
}

fn Boolean.new(value bool) Boolean {
	return Boolean{
		value: value
	}
}

fn Boolean.new_with_tag(value bool, tag asn1.Tag) Boolean {
	return Boolean{
		value: value
		tag: tag
	}
}

fn (v Boolean) tag() asn1.Tag {
	return v.tag
}

fn (v Boolean) packed_length() int {
	mut n := 0
	n += v.tag().packed_length()
	// boolean length should 1
	n += 1
	n += 1

	return n
}

fn (v Boolean) pack_to_asn1(mut to []u8, mode asn1.EncodingMode, p asn1.Params) ! {
	match mode {
		.ber, .der {
			// in DER/BER, true or false value packed to single byte of 0xff or 0x00 respectively
			v.tag().pack_to_asn1(mut to, mode, p)!
			length := asn1.Length.from_i64(1)!
			length.pack_to_asn1(mut to, mode, p)!
			if v.value {
				to << u8(0xff)
			} else {
				to << u8(0x00)
			}
		}
		else {
			return error('unsupported mode')
		}
	}
}

fn Boolean.unpack_from_asn1(b []u8, loc i64, mode asn1.EncodingMode, p asn1.Params) !(Boolean, i64) {
	if b.len < 3 {
		return error('Boolean: bad length bytes')
	}
	match mode {
		.ber, .der {
			tag, pos := asn1.Tag.unpack_from_asn1(b, loc, mode, p)!
			if tag.class() != .universal || tag.is_compound()
				|| tag.tag_number() != int(asn1.TagType.boolean) {
				return error('Boolean: bad tag of universal class type')
			}
			len, idx := asn1.Length.unpack_from_asn1(b, pos, mode, p)!
			// boolean value should be encoded in single byte
			if len != 1 {
				return error('der encoding of boolean value represented in multibytes is not allowed')
			}
			if idx > b.len {
				return error('Boolean: truncated input')
			}
			bytes := unsafe { b[idx..idx + len] }
			assert bytes.len == 1
			b0 := bytes[0]
			match b0 {
				0x00 {
					return Boolean{
						tag: tag
						value: false
					}, idx + len
				}
				// 0xff packed to true value
				0xff {
					return Boolean{
						tag: tag
						value: true
					}, idx + len
				}
				else {
					// in der, other values is not allowed, but allowed in ber
					if mode == .der {
						return error('Boolean: not allowed for true value')
					}
					return Boolean{
						tag: tag
						value: true
					}, idx + len
				}
			}
		}
		else {
			return error('Unsupported mode')
		}
	}
}
