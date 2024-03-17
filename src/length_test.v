// Copyright (c) 2022, 2023 blackshirt. All rights reserved.
// Use of this source code is governed by a MIT License
// that can be found in the LICENSE file.
module asn1

struct LengthPackTest {
	value    i64
	expected []u8
	err      IError
}

fn test_length_pack_and_unpack_tofrom_asn() ! {
	edata := [
		LengthPackTest{0, [u8(0x00)], none},
		LengthPackTest{10, [u8(0x0a)], none},
		LengthPackTest{127, [u8(0x7f)], none},
		LengthPackTest{255, [u8(0x81), 0xff], none},
		LengthPackTest{256, [u8(0x82), 0x01, 0x00], none},
		LengthPackTest{383, [u8(0x82), 0x01, 127], none},
		LengthPackTest{257, [u8(0x82), 0x01, 0x01], none},
		LengthPackTest{65535, [u8(0x82), 0xff, 0xff], none},
		LengthPackTest{65536, [u8(0x83), 0x01, 0x00, 0x00], none},
		LengthPackTest{16777215, [u8(0x83), 0xff, 0xff, 0xff], none},
	]
	for i, c in edata {
		mut dst := []u8{}
		s := Length.from_i64(c.value)!
		s.pack_to_asn1(mut dst, .der)!
		assert dst == c.expected

		length, idx := Length.unpack_from_asn1(dst, 0, .der)!

		assert length == c.value
		assert idx == c.expected.len
	}
}

struct ByteLengthTest {
	value    i64
	expected []u8
}

fn test_basic_simple_length_unpack() {
	data := [u8(0x82), 0x01, 0x7F]
	n, pos := Length.unpack_from_asn1(data, 0, .der)!

	assert n == 383
	assert pos == 3

	data2 := [u8(0x82), 0x01, 0x31]
	n2, pos2 := Length.unpack_from_asn1(data2, 0, .der)!
	assert n2 == 305
	assert pos2 == 3
}

fn test_length_pack_and_append() ! {
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

	for v in bdata {
		mut dst := []u8{}
		ln := Length.from_i64(v.value)!
		ln.pack_and_append(mut dst)

		assert dst == v.expected
	}
}

struct LengthTest {
	value    i64
	expected int
}

fn test_length_bytes_len() ! {
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
	]

	for c in ldata {
		len := Length.from_i64(c.value)!
		out := len.bytes_len()

		assert out == c.expected
	}
}

fn test_calc_length_of_length() ! {
	data := [
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
	]

	for c in data {
		len := Length.from_i64(c.value)!
		out := len.packed_length()

		assert out == c.expected
	}
}

// ASN.1 Test Suite from https://github.com/YuryStrozhevsky/asn1-test-suite
fn test_tc3_absence_standard_length_block() ! {
	value := []u8{}

	_, _ := Length.unpack_from_asn1(value, 0, .der) or {
		assert err == error('Length: truncated length')
		return
	}
}

fn test_tc5_unnecessary_usage_long_of_length_form() ! {
	value := [u8(0x9f), 0xff, 0x7f, 0x81, 0x01, 0x40]

	tag, pos := Tag.unpack_from_asn1(value, 0, .der)!
	// 0x9f == 10011111
	assert tag.cls == .context_specific
	assert tag.constructed == false
	assert pos == 3
	// the length bytes, [0x81, 0x01] dont needed in long form.
	_, _ := Length.unpack_from_asn1(value, pos, .der) or {
		assert err == error('Length: dont needed in long form')
		return
	}
}
