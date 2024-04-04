// Copyright (c) 2022, 2023 blackshirt. All rights reserved.
// Use of this source code is governed by a MIT License
// that can be found in the LICENSE file.
module asn1

fn test_read_boolean() {
	b1 := [u8(0x00)]
	// tag := new_tag(.universal, false, int(TagType.boolean))
	o1 := read_boolean(b1)!

	assert o1 == false
	b2 := [u8(0xff)]
	o2 := read_boolean(b2)!

	assert o2 == true
}

fn test_encode_boolean() {
	f := encode_boolean(false)
	assert f == [u8(TagType.boolean), 0x01, 0x00]
	t := encode_boolean(true)
	assert t == [u8(TagType.boolean), 0x01, 0xff]
}

struct BooleanTest {
	inp []u8
	out bool
	err IError
}

fn test_encode_decode_boolean() {
	bd := [
		BooleanTest{[u8(TagType.boolean), 0x01, 0xff], true, none},
		BooleanTest{[u8(TagType.boolean), 0x01, 0x00], false, none},
		BooleanTest{[u8(TagType.boolean), 0x01, 0x10], false, error('bad boolean contents argument')}, // invalid value
		BooleanTest{[u8(TagType.boolean), 0x02, 0x00], false, error('bad boolean contents argument')}, // bad length
		BooleanTest{[u8(TagType.integer), 0x01, 0x00], false, error('bad boolean contents argument')}, // bad tag number
	]
	for c in bd {
		out := decode_boolean(c.inp) or {
			assert err == c.err
			continue
		}
		o1 := out.as_boolean()!
		assert o1 == c.out

		back := encode_boolean(o1)
		assert back == c.inp
	}
}
