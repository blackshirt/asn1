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
	tag   Tag = Tag{.universal, false, int(TagType.boolean)}
	value bool
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

pub fn (v Boolean) encode(mut dst []u8, p Params) ! {
	if p.mode != .der && p.mode != .ber {
		return error('BitString: unsupported mode')
	}

	// in DER/BER, true or false value packed into single byte of 0xff or 0x00 respectively
	v.tag().encode(mut dst, p)!
	length := Length.from_i64(1)!
	length.encode(mut dst, p)!
	if v.value {
		dst << u8(0xff)
	} else {
		dst << u8(0x00)
	}
}

pub fn Boolean.decode(src []u8, loc i64, p Params) !(Boolean, i64) {
	if src.len < 3 {
		return error('Boolean: bad length bytes')
	}
	tlv, next := Tlv.read(src, loc, p)!

	if tlv.tag.class() != .universal || tlv.tag.is_constructed()
		|| tlv.tag.tag_number() != int(TagType.boolean) {
		return error('Boolean: bad tag of universal class type')
	}
	// boolean value should be encoded in single byte
	if tlv.length != 1 {
		return error('der encoding of boolean value represented in multibytes is not allowed')
	}

	assert tlv.content.len == 1
	mut value := false
	match tlv.content[0] {
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
		tag: tlv.tag
	}, next
}
