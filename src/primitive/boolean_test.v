// Copyright (c) 2022, 2023 blackshirt. All rights reserved.
// Use of this source code is governed by a MIT License
// that can be found in the LICENSE file.
module primitive

struct BooleanTest {
	inp []u8
	out bool
	err IError
}

fn test_encode_decode_boolean_in_der_mode() {
	bd := [
		BooleanTest{[u8(1), 0x01, 0xff], true, none},
		BooleanTest{[u8(1), 0x01, 0x00], false, none},
		BooleanTest{[u8(1), 0x01, 0x10], false, error('Boolean: not allowed for true value')}, // invalid value
		BooleanTest{[u8(1), 0x02, 0x00], false, error('der encoding of boolean value represented in multibytes is not allowed')}, // bad length
		BooleanTest{[u8(1), 0x01, 0x00], false, error('Boolean: bad tag of universal class type')}, // bad tag number
	]
	for i, c in bd {
		dump(i)
		out, pos := Boolean.unpack_from_asn1(c.inp, 0, .der) or {
			assert err == c.err
			continue
		}

		assert out.b == c.out
	}
}
