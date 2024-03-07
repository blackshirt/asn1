// Copyright (c) 2022, 2023 blackshirt All rights reserved.
// Use of this source code is governed by a MIT License
// that can be found in the LICENSE file.
module primitive

import math
import math.big
import encoding.hex

struct FromString {
	value    string
	expected string
}

const string_data = [
	FromString{'0', '\x00'},
	FromString{'25', '\x19'},
	FromString{'100', '\x64'},
	FromString{'-1042342234234123423435647768234', '\xF2\xD8\x02\xB6R\x7F\x99\xEE\x98#\x99\xA9V'},
	FromString{'-12095473475870063', '\xD5\a;\x20\x14\xA2\x91'},
	FromString{'12095473475870063', '*\xF8\xC4\xDF\xEB]o'},
	FromString{'12438789579431234124191998', '\nJ\x04"^\x91\x04\x8a\xb1\x18\xfe'},
	FromString{'-112233441191', '\xe5\xde]\x98Y'},
	FromString{'64206', '\x00\xfa\xce'},
	FromString{'-100', '\x9C'},
	FromString{'100', '\x64'},
	FromString{'255', '\x00\xFF'},
	FromString{'0', '\x00'},
	FromString{'-2', '\xfe'},
	FromString{'-1', '\xff'},
	FromString{'-16', '\xf0'},
	FromString{'-256', '\xff\x00'},
	FromString{'-255', '\xff\x01'},
	FromString{'-32768', '\x80\x00'},
	FromString{'-128', '\x80'},
	FromString{'-129', '\xff\x7f'},
	FromString{'-127', '\x81'},
]

fn test_pack_integer_into_2form_from_string_data() ! {
	for i, c in primitive.string_data {
		v := Integer.from_string(c.value)!
		out, _ := v.pack_into_twoscomplement_form()!

		assert out == c.expected.bytes()

		// back
		b := Integer.unpack_from_twoscomplement_bytes(c.expected.bytes())!
		assert b.value.str() == c.value
	}
}

struct UnpackTest {
	val i64
	out []u8
}

// from python asn1tools
//
const unpack_data = [
	UnpackTest{32768, [u8(0x02), 0x03, 0x00, 0x80, 0x00]},
	UnpackTest{32767, [u8(0x02), 0x02, 0x7f, 0xff]},
	UnpackTest{256, [u8(0x02), 0x02, 0x01, 0x00]},
	UnpackTest{255, [u8(0x02), 0x02, 0x00, 0xff]},
	UnpackTest{128, [u8(0x02), 0x02, 0x00, 0x80]},
	UnpackTest{127, [u8(0x02), 0x01, 0x7f]},
	UnpackTest{1, [u8(0x02), 0x01, 0x01]},
	UnpackTest{0, [u8(0x02), 0x01, 0x00]},
	UnpackTest{-1, [u8(0x02), 0x01, 0xff]},
	UnpackTest{-128, [u8(0x02), 0x01, 0x80]},
	UnpackTest{-129, [u8(0x02), 0x02, 0xff, 0x7f]},
	UnpackTest{-256, [u8(0x02), 0x02, 0xff, 0x00]},
	UnpackTest{-32768, [u8(0x02), 0x02, 0x80, 0x00]},
	UnpackTest{-32769, [u8(0x02), 0x03, 0xff, 0x7f, 0xff]},
]

fn test_asn1_integer_unpack_to_asn1() ! {
	for i, c in primitive.unpack_data {
		n := Integer.from_i64(c.val)
		mut to := []u8{}
		n.pack_to_asn1(mut to, .der)!
		assert to == c.out
	}
}

struct IntegerTest {
	bytes    []u8
	err      IError
	expected big.Integer
}

const integer_test_data = [
	IntegerTest{[u8(0x00)], none, zero_integer},
	IntegerTest{[u8(0x7f)], none, big.integer_from_int(127)},
	IntegerTest{[u8(0x00), 0x80], none, big.integer_from_int(128)},
	IntegerTest{[u8(0x01), 0x00], none, big.integer_from_int(256)},
	IntegerTest{[u8(0x80)], none, big.integer_from_int(-128)},
	IntegerTest{[u8(0xff), 0x7f], none, big.integer_from_int(-129)},
	IntegerTest{[u8(0xff)], none, big.integer_from_int(-1)},
	IntegerTest{[u8(0x80), 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00], none, big.integer_from_i64(-9223372036854775808)},
	IntegerTest{[u8(0x80), 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00], error('too large integer'), big.integer_from_string('-2361183241434822606848') or {
		panic(err)
	}},
	IntegerTest{[], error('Integer: check return false'), zero_integer},
	IntegerTest{[u8(0x00), 0x7f], error('Integer: check return false'), big.integer_from_int(127)}, // non-minimal form
	IntegerTest{[u8(0xff), 0xf0], error('Integer: check return false'), big.integer_from_int(-16)}, // non-minimal form
]

// from golang encoding/asn1 test
fn test_asn1_integer_read_bigint() {
	for i, v in primitive.integer_test_data {
		ret := read_bigint(v.bytes) or {
			assert err == v.err
			continue
		}

		assert ret == v.expected
	}
}

fn test_asn1_unpack_and_validate() {
	for i, v in primitive.integer_test_data {
		ret := Integer.unpack_and_validate(v.bytes) or {
			assert err == v.err
			continue
		}

		assert ret.value == v.expected
	}
}


/*
struct I32Test {
	bytes []u8
	err IError
	expected i32
}

fn test_read_i32() {
	i32testdata := [
		I32Test{[], error('i32 check return false'), 0}, // empty integer
		I32Test{[u8(0x00)], none, 0},
		I32Test{[u8(0x7f)], none, 127},
		I32Test{[u8(0x00), 0x80], none, 128},
		I32Test{[u8(0x01), 0x00], none, 256},
		I32Test{[u8(0x80)], none, -128},
		I32Test{[u8(0xff), 0x7f], none, -129},
		I32Test{[u8(0x80), 0x00, 0x00, 0x00], none, -2147483648},
		I32Test{[u8(0x80), 0x00, 0x00, 0x00, 0x00], error('integer too large'), 0}, // overflow too big
		I32Test{[u8(0x00), 0x7f], error('i32 check return false'), 0},
		I32Test{[u8(0xff), 0xf0], error('i32 check return false'), 0}, // not minimally
	]
	for i, test in i32testdata {
		ret := read_i32(test.bytes) or {
			assert err == test.err
			continue
		}
		assert ret == test.expected
	}
}

struct BigintTest {
	bytes []u8
	err IError
	expected string
}

fn test_read_bigint() {
	bigint_data := [
		BigintTest{[u8(0xff)], none, '-1'},
		BigintTest{[u8(0x00)], none, '0'},
		BigintTest{[u8(0x01)], none, '1'},
		BigintTest{[u8(0x00), 0xff], none, '255'},
		BigintTest{[u8(0xff), 0x00], none, '-256'},
		BigintTest{[u8(0x01), 0x00], none, '256'},
		BigintTest{[], error('big integer check return false'), '0'}, // empty
		BigintTest{[u8(0x00), 0x7f], error('big integer check return false'), ''}, // not minimally encoded
		BigintTest{[u8(0xff), 0xf0], error('big integer check return false'), ''}, // not minimally encoded
		BigintTest{'\0xff\0x7f\0xff\0xff\0xff\0xff\0xff\0xff\0xff\0xff\0xff\0xff'.bytes(), error('big integer check return false'), ''},
	]

	for i, test in bigint_data {
		ret := read_bigint(test.bytes) or {
			assert err == test.err
			continue
		}
		assert ret.str() == test.expected
	}
}

struct I64SerializeTest {
	bytes i64
	out string
}

fn test_serialize_decode_i64() {
	ds := [
		I64SerializeTest{10, '02010a'},
		I64SerializeTest{127, '02017f'},
		I64SerializeTest{128, '02020080'},
		I64SerializeTest{-128, '020180'},
		I64SerializeTest{-129, '0202ff7f'},
		I64SerializeTest{-256, '0202ff00'},
		I64SerializeTest{666, '0202029a'},
		I64SerializeTest{86424278346, '0205141f49d54a'},
		I64SerializeTest{math.max_i64, '02087fffffffffffffff'},
		// from rust-asn1
		I64SerializeTest{-256, '0202ff00'},
	]

	for t in ds {
		out := serialize_i64(i64(t.bytes))!
		exp := hex.decode(t.out)!

		assert out == exp

		tag, back := decode_i64(exp)!

		assert back == t.bytes
		assert tag.number == 0x02 // integer

		num := new_integer(t.bytes)
		assert num.encode()! == exp
	}
}

struct I32SerializeTest {
	bytes string
	out i32
	err IError
}

fn test_serialize_decode_i32() ! {
	ds := [
		I32SerializeTest{'020100', 0, none},
		I32SerializeTest{'02017f', 127, none},
		I32SerializeTest{'02020080', 128, none},
		I32SerializeTest{'02020100', 256, none},
		I32SerializeTest{'020180', -128, none},
		I32SerializeTest{'0202ff7f', -129, none},
		I32SerializeTest{'0202ff00', -256, none},
		I32SerializeTest{'02047fffffff', math.max_i32, none},
		// bad tag
		I32SerializeTest{'0300', 0, error('bad tag')}, // fall in check validity
	]

	for c in ds {
		bytes := hex.decode(c.bytes)!
		tag, val := decode_i32(bytes) or {
			assert err == c.err
			continue
		}

		assert val == c.out
		assert tag.number == 0x02 // integer

		// serialize back
		ser := serialize_i32(val)!
		assert ser == bytes
	}
}

fn test_bigint_basic() ! {
	bytes := big.integer_from_bytes([u8(0x13), 0x37, 0xca, 0xfe, 0xba, 0xbe])
	out := [u8(0x02), 6, u8(0x13), 0x37, 0xca, 0xfe, 0xba, 0xbe]
	// bytes == val
	val := big.integer_from_i64(i64(0x1337cafebabe))

	s := serialize_bigint(bytes)!
	assert s == out

	// back
	tag, back := decode_bigint(out)!

	assert tag.number == int(TagType.integer)
	assert back == val
}

fn test_bigint_advanced() ! {
	bytes := big.integer_from_string('84885164052257330097714121751630835360966663883732297726369399')!
	out := [u8(0x02), 26, 52, 210, 252, 160, 105, 66, 145, 88, 8, 53, 227, 150, 221, 98, 149, 87,
		146, 121, 109, 20, 162, 246, 230, 65, 30, 119]

	s := serialize_bigint(bytes)!
	assert s == out

	// back
	tag, back := decode_bigint(out)!

	assert tag.number == int(TagType.integer)
	assert back == bytes
}

struct Intest {
	num int
	out []u8
}

fn test_asn1_integer_serializing() ! {
	data := [Intest{32768, [u8(0x02), 0x03, 0x00, 0x80, 0x00]},
		Intest{32767, [u8(0x02), 0x02, 0x7f, 0xff]}, Intest{256, [u8(0x02), 0x02, 0x01, 0x00]},
		Intest{255, [u8(0x02), 0x02, 0x00, 0xff]}, Intest{128, [u8(0x02), 0x02, 0x00, 0x80]},
		Intest{127, [u8(0x02), 0x01, 0x7f]}, Intest{1, [u8(0x02), 0x01, 0x01]},
		Intest{0, [u8(0x02), 0x01, 0x00]}, Intest{-1, [u8(0x02), 0x01, 0xff]},
		Intest{-128, [u8(0x02), 0x01, 0x80]}, Intest{-129, [u8(0x02), 0x02, 0xff, 0x7f]},
		Intest{-256, [u8(0x02), 0x02, 0xff, 0x00]}, Intest{-32768, [u8(0x02), 0x02, 0x80, 0x00]},
		Intest{-32769, [u8(0x02), 0x03, 0xff, 0x7f, 0xff]}]
	for c in data {
		num := new_integer(c.num)
		out := num.encode()!
		assert out == c.out
	}
}

fn test_tc19_non_finished_encoding() ! {
	data := [u8(0x02), 0x001]
	_, _ := decode_i32(data) or {
		assert err == error('pos + size maybe getting overflow')
		return
	}
}
*/
