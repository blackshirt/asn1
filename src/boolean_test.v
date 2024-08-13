// Copyright (c) 2022, 2023 blackshirt. All rights reserved.
// Use of this source code is governed by a MIT License
// that can be found in the LICENSE file.
module asn1

struct BooleanTest {
	inp []u8
	out bool
	err IError
}

fn test_encode_decode_boolean_in_der_mode() {
	bd := [
		BooleanTest{[u8(1), 0x01, 0xff], true, none},
		BooleanTest{[u8(1), 0x01, 0x00], false, none},
		BooleanTest{[u8(1), 0x01, 0x10], false, error('Boolean: in DER, other than 0xff is not allowed for true value')}, // invalid value
		BooleanTest{[u8(1), 0x02, 0x00], false, error('RawElement: truncated src bytes')}, // bad length
		BooleanTest{[u8(1), 0x01, 0x00], false, error('Boolean: bad tag of universal class type')}, // bad tag number
	]
	for c in bd {
		out, pos := Boolean.decode(c.inp, 0) or {
			assert err == c.err
			continue
		}
		// out.value is now u8, call .value() instead
		assert out.value() == c.out
	}
}
