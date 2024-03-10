// Copyright (c) 2022, 2023 blackshirt. All rights reserved.
// Use of this source code is governed by a MIT License
// that can be found in the LICENSE file.
module primitive

import asn1

// ASN.1 NULL TYPE
struct Null {}

fn Null.new() Null {
	return Null{}
}

fn (n Null) length() int {
	return 0
}

fn (n Null) packed_length() int {
	return 2
}

fn (n Null) tag() !asn1.Tag {
	return asn1.new_tag(.universal, false, 5)
}

fn (n Null) pack_to_asn1(mut to []u8, mode asn1.EncodingMode, p asn1.Params) ! {
	match mode {
		.der {
			n.tag()!.pack_to_asn1(mut to, .der, p)!
			// the length is 0
			to << [u8(0x00)]
		}
		else {
			return error('unsupported mode')
		}
	}
}

fn Null.unpack(b []u8, loc i64, mode asn1.EncodingMode, p asn1.Params) !(Null, i64) {
	match mode {
		.der {
			if b.len < 2 {
				return error('Null: invalid args')
			}
			tag, pos := asn1.Tag.unpack_from_asn1(b, loc, .der, p)!
			if tag.tag_number() != 0x05 {
				return error('Null: bad tag=${tag}')
			}
			len, idx := asn1.Length.unpack_from_asn1(b, pos, .der, p)!
			if len != 0 {
				return error('Null: len != 0')
			}
			return Null{}, idx
		}
		else {
			return error('unsupported mode')
		}
	}
}

fn (n Null) str() string {
	return 'NULL'
}
