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
struct Boolean {
	value bool
mut:
	tag Tag = new_tag(.universal, false, int(TagType.boolean))!
}

fn Boolean.new(value bool) Boolean {
	return Boolean{
		value: value
	}
}

fn Boolean.new_with_tag(value bool, tag Tag) Boolean {
	return Boolean{
		value: value
		tag: tag
	}
}

fn (v Boolean) tag() Tag {
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

fn (v Boolean) pack_to_asn1(mut dst []u8, p Params) ! {
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

fn Boolean.unpack_from_asn1(src []u8, loc i64, p Params) !(Boolean, i64) {
	if src.len < 3 {
		return error('Boolean: bad length bytes')
	}
	if p.mode != .der && p.mode != .ber {
		return error('Boolean: unsupported mode')
	}
	if loc > src.len {
		return error('Boolean: bad position offset')
	}

	tag, pos := Tag.unpack_from_asn1(src, loc, mode, p)!
	if tag.class() != .universal || tag.is_constructed() || tag.tag_number() != int(TagType.boolean) {
		return error('Boolean: bad tag of universal class type')
	}
	len, idx := Length.unpack_from_asn1(src, pos, mode, p)!
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
			if mode == .der {
				return error('Boolean: not allowed for true value')
			}
			value = true
		}
	}
	return Boolean{
		value: value
		tag: tag
	}, idx + len
}
