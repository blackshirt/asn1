// Copyright (c) 2022, 2023 blackshirt. All rights reserved.
// Use of this source code is governed by a MIT License
// that can be found in the LICENSE file.
module asn1

fn test_read_boolean() {
	b1 := [u8(0x00)]
	// tag := new_tag(.universal, false, int(TagType.boolean))
	o1 := read_boolean(b1)!

	if o1 is AsnBoolean {
		assert o1.value == false
	}
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
		BooleanTest{[u8(TagType.boolean), 0x01, 0x10], false, error('boolean: invalid args of src')}, // invalid value
		BooleanTest{[u8(TagType.boolean), 0x02, 0x00], false, error('boolean: invalid args of src')}, // bad length
		BooleanTest{[u8(TagType.integer), 0x01, 0x00], false, error('boolean: invalid args of src')}, // bad tag number
	]
	for c in bd {
		out := decode_boolean(c.inp) or {
			assert err == c.err
			continue
		}
		assert out is AsnBoolean
		if out is AsnBoolean {
			assert out.value == c.out
		}

		// back
		if out is AsnBoolean {
			back := encode_boolean(out.value)
			assert back == c.inp
		}
	}
}
