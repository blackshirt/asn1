// Copyright (c) 2022, 2023 blackshirt. All rights reserved.
// Use of this source code is governed by a MIT License
// that can be found in the LICENSE file.
module asn1

struct LengthEncodeTest {
	inp int
	exp []u8
}

fn test_serialize_length() ! {
	edata := [
		LengthEncodeTest{0, [u8(0x00)]},
		LengthEncodeTest{10, [u8(0x0a)]},
		LengthEncodeTest{127, [u8(0x7f)]},
		LengthEncodeTest{255, [u8(0x81), 0xff]},
		LengthEncodeTest{256, [u8(0x82), 0x01, 0x00]},
		LengthEncodeTest{383, [u8(0x82), 0x01, 127]},
		LengthEncodeTest{257, [u8(0x82), 0x01, 0x01]},
		LengthEncodeTest{65535, [u8(0x82), 0xff, 0xff]},
		LengthEncodeTest{65536, [u8(0x83), 0x01, 0x00, 0x00]},
		LengthEncodeTest{16777215, [u8(0x83), 0xff, 0xff, 0xff]},
	]
	for c in edata {
		mut dst := []u8{}
		dst = serialize_length(mut dst, c.inp)
		assert dst == c.exp

		length, idx := decode_length(dst, 0)!

		assert length == c.inp
		assert idx == c.exp.len
	}
}

struct ByteLengthTest {
	inp int
	exp []u8
}

fn test_decode_length() {
	data := [u8(0x82), 0x01, 0x7F]

	n, pos := decode_length(data, 0)!
	assert n == 383
	assert pos == 3

	data2 := [u8(0x82), 0x01, 0x31]
	n2, pos2 := decode_length(data2, 0)!
	assert n2 == 305
	assert pos2 == 3
}

fn test_append_length() {
	bdata := [
		ByteLengthTest{1, [u8(1)]},
		ByteLengthTest{127, [u8(0x7f)]},
		ByteLengthTest{255, [u8(0xff)]},
		ByteLengthTest{256, [u8(0x01), 0x00]},
		ByteLengthTest{383, [u8(0x01), 127]},
		ByteLengthTest{257, [u8(0x01), 0x01]},
		ByteLengthTest{7967, [u8(0x1f), 0x1f]},
		ByteLengthTest{65535, [u8(0xff), 0xff]},
		ByteLengthTest{65537, [u8(0x01), 0x00, 0x01]},
		ByteLengthTest{16777215, [u8(0xff), 0xff, 0xff]},
	]

	for i in bdata {
		mut dst := []u8{}
		out := append_length(mut dst, i.inp)

		assert out == i.exp
	}
}

struct LengthTest {
	inp int
	exp int
}

fn test_calc_length() {
	ldata := [
		LengthTest{1, 1},
		LengthTest{128, 1},
		LengthTest{255, 1},
		LengthTest{256, 2},
		LengthTest{383, 2},
		LengthTest{65535, 2},
		LengthTest{65536, 3},
		LengthTest{16777215, 3},
		LengthTest{16777216, 4},
		LengthTest{2147483647, 4}, // math.max_i32
		// LengthTest{4294967295, 4}, // math.max_u32, its silently overflow
	]

	for c in ldata {
		out := calc_length(c.inp)

		assert out == c.exp
	}
}

fn test_calc_length_of_length() {
	ldata := [
		LengthTest{1, 1},
		LengthTest{128, 2},
		LengthTest{255, 2},
		LengthTest{256, 3},
		LengthTest{383, 3},
		LengthTest{65535, 3},
		LengthTest{65536, 4},
		LengthTest{16777215, 4},
		LengthTest{16777216, 5},
		LengthTest{2147483647, 5}, // math.max_i32
		// LengthTest{4294967295, 4}, // math.max_u32, its silently overflow
	]

	for c in ldata {
		// dump(i)
		out := calc_length_of_length(c.inp)

		assert out == c.exp
	}
}
