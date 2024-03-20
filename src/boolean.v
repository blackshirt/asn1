// Copyright (c) 2022, 2023 blackshirt. All rights reserved.
// Use of this source code is governed by a MIT License
// that can be found in the LICENSE file.
module asn1

// ASN.1 BOOLEAN
//
// A Boolean value can take true or false.
// ASN.1 DER encoding restricts encoding of boolean true value into 0xff
// and otherwise, encodes into zero (0x00) for false value.
// The encoding of a boolean value shall be primitive. The contents octets shall consist of a single octet.
pub struct Boolean {
	value bool
mut:
	tag Tag = new_tag(.universal, false, int(TagType.boolean))!
}

pub fn Boolean.new(value bool) Boolean {
	return Boolean{
		value: value
	}
}

pub fn Boolean.from_bytes(b []u8) !Boolean {
	if b.len != 1 {
		return error('Boolean: bad bytes')
	}
	if b[0] == u8(0x00) {
		return Boolean.new(false)
	}
	if b[0] == u8(0xff) {
		return Boolean.new(true)
	}
	// other values is not supported
	return error('Boolean: unsupported value')
}

pub fn (v Boolean) tag() Tag {
	return v.tag
}

pub fn (v Boolean) length(p Params) int {
	return 1
}

pub fn (v Boolean) payload(p Params) ![]u8 {
	if v.value {
		return [u8(0xff)]
	}
	return [u8(0x00)]
}

pub fn (v Boolean) packed_length(p Params) int {
	mut n := 0
	n += v.tag().packed_length(p)
	// boolean length should 1
	n += 1
	n += 1

	return n
}

pub fn (v Boolean) pack_to_asn1(mut dst []u8, p Params) ! {
	if p.mode != .der && p.mode != .ber {
		return error('BitString: unsupported mode')
	}

	// in DER/BER, true or false value packed into single byte of 0xff or 0x00 respectively
	v.tag().pack_to_asn1(mut dst, p)!
	length := Length.from_i64(1)!
	length.pack_to_asn1(mut dst, p)!
	if v.value {
		dst << u8(0xff)
	} else {
		dst << u8(0x00)
	}
}

pub fn Boolean.unpack_from_asn1(src []u8, loc i64, p Params) !(Boolean, i64) {
	if src.len < 3 {
		return error('Boolean: bad length bytes')
	}
	if p.mode != .der && p.mode != .ber {
		return error('Boolean: unsupported mode')
	}
	if loc > src.len {
		return error('Boolean: bad position offset')
	}

	tag, pos := Tag.unpack_from_asn1(src, loc, p)!
	if tag.class() != .universal || tag.is_constructed() || tag.tag_number() != int(TagType.boolean) {
		return error('Boolean: bad tag of universal class type')
	}
	len, idx := Length.unpack_from_asn1(src, pos, p)!
	// boolean value should be encoded in single byte
	if len != 1 {
		return error('der encoding of boolean value represented in multibytes is not allowed')
	}
	if idx > src.len || idx + len > src.len {
		return error('Boolean: truncated input')
	}
	bytes := unsafe { src[idx..idx + len] }
	assert bytes.len == 1
	b0 := bytes[0]
	mut value := false
	match b0 {
		// 0x00 unpacked into false value
		0x00 {
			value = false
		}
		// 0xff unpacked into true value
		0xff {
			value = true
		}
		else {
			// in der, other values is not allowed, but allowed in ber
			if p.mode == .der {
				return error('Boolean: in DER, other than 0xff is not allowed for true value')
			}
			value = true
		}
	}
	return Boolean{
		value: value
		tag: tag
	}, idx + len
}
