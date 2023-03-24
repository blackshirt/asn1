// Copyright (c) 2022, 2023 blackshirt. All rights reserved.
// Use of this source code is governed by a MIT License
// that can be found in the LICENSE file.
module asn1

struct OidWriteTest {
	inp []int
	exp []u8
	err IError
}

fn test_write_oid() ! {
	dt := [
		OidWriteTest{[], [], error('bad oid int array')}, // empty arc
		OidWriteTest{[0], [u8(0x00)], error('bad oid int array')}, // only root arc
		OidWriteTest{[0, 0], [u8(0x00)], none},
		OidWriteTest{[3, 0], [u8(0x00)], error('bad oid int array')}, // first arc, 3 is not allowed value
		OidWriteTest{[0, 40], [u8(0x00)], error('bad oid int array')}, // second arc, 40 is not allowed (its should <= 39)
		OidWriteTest{[1, 40], [u8(0x00)], error('bad oid int array')}, // second arc, 40 is not allowed (its should <= 39)
		OidWriteTest{[1, 2], [u8(0x2a)], none},
		OidWriteTest{[2, 5], [u8(0x55)], none},
		OidWriteTest{[1, 2, 840], [u8(0x2a), 0x86, 0x48], none},
		OidWriteTest{[1, 2, 840, 113549], [u8(0x2a), 0x86, 0x48, 0x86, 0xF7, 0x0D], none},
		OidWriteTest{[1, 2, 840, 113549, 1], [u8(0x2a), 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01], none},
	]

	for item in dt {
		val := oid_from_ints(item.inp) or {
			assert err == item.err
			continue
		}
		mut dst := []u8{}
		write_oid(mut dst, val)

		assert dst == item.exp
	}
}

struct BuildOidTest {
	inp []int
	out Oid
	err IError
}

fn test_oid_from_ints() ! {
	td := [
		BuildOidTest{[1, 2], [1, 2], none},
		BuildOidTest{[1, 2, 3], [1, 2, 3], none},
		BuildOidTest{[1, 4, 4], [1, 4, 4], none},
		BuildOidTest{[1, 39, 6, 256], [1, 39, 6, 256], none},
		// second >= 40 when first < 2 not allowed
		BuildOidTest{[1, 40, 4], [1, 40, 4], error('bad oid int array')},
		// first value bigger than 2 was not allowed
		BuildOidTest{[4, 5, 6], [4, 5, 6], error('bad oid int array')},
		// second value >= 40 was not allowed when first < 2
		BuildOidTest{[1, 40, 6], [1, 40, 6], error('bad oid int array')},
		BuildOidTest{[2, 50, 6], [2, 50, 6], error('bad oid int array')},
		BuildOidTest{[1, 4, 4555555555555555555], [1, 4, 4555555555555555555], error('overflow parse_int result')},
		BuildOidTest{[4, 0xab, 4], [4, 0xab, 4], error('bad oid int array')},
		BuildOidTest{[4, 0x0c, 4], [4, 0x0c, 4], error('bad oid int array')},
		BuildOidTest{[2], [2], error('bad oid int array')},
	]
	for i, c in td {
		s := oid_from_ints(c.inp) or {
			assert err == c.err
			continue
		}
		assert s == c.out
	}
}

struct OidStrTest {
	inp string
	out Oid
	err IError
}

fn test_oid_from_string() ! {
	td := [
		OidStrTest{'1.2.840.113549', [1, 2, 840, 113549], none},
		OidStrTest{'1.3.6.1.3', [1, 3, 6, 1, 3], none},
		OidStrTest{'1.2', [1, 2], none},
		OidStrTest{'1.4.4', [1, 4, 4], none},
		OidStrTest{'1.4.x', [1, 4, 4], error('common_parse_uint: syntax error x')}, // invalid char
		OidStrTest{'4.4.4', [4, 4, 4], error('bad oid string')},
		OidStrTest{'1.4.4555555555555555555', [4, 4, 4555555555555555555], error('common_parse_uint: integer overflow 4555555555555555555')},
		OidStrTest{'4.ab.4', [4, 0xab, 4], error('common_parse_uint: syntax error ab')}, // invalid char
		OidStrTest{'4.c.4', [4, 0x0c, 4], error('common_parse_uint: syntax error c')}, // invalid char
		OidStrTest{'2', [2], error('bad string oid length')},
	]
	for s in td {
		v := oid_from_string(s.inp) or {
			assert err == s.err
			continue
		}
		assert v == s.out
	}
}

fn test_serialize_oid_basic() {
	// https://www.oss.com/asn1/resources/asn1-made-simple/asn1-quick-reference/object-identifier.html
	inp := [1, 0, 8571, 2, 1]
	exp := [u8(6), 5, 0x28, 0xC2, 0x7B, 0x02, 0x01]
	oid := oid_from_ints(inp)!

	out := serialize_oid(oid)!

	assert out == exp
}

struct OidSerializeTest {
	inp []int
	exp []u8
	err IError
}

fn test_serialize_decode_oid() {
	td := [
		OidSerializeTest{[0, 0], [u8(0x06), 0x01, 0x00], none},
		OidSerializeTest{[1, 2, 3], [u8(0x06), 0x02, 0x2a, 0x03], none},
		OidSerializeTest{[1, 3, 6, 1, 3], [u8(0x06), 0x04, 0x2b, 0x06, 1, 3], none},
		OidSerializeTest{[2, 999, 1234], [u8(0x06), 0x04, 0x88, 0x37, 0x89, 0x52], none},
		OidSerializeTest{[2, 999, 3], [u8(0x06), 0x03, 0x88, 0x37, 0x03], none}, // Example of ITU-T X.690
		// from https://learn.microsoft.com/en-us/windows/win32/seccertenroll/about-object-identifier
		OidSerializeTest{[1, 3, 6, 1, 4, 1, 311, 21, 20], [u8(0x06), 0x09, 0x2b, 0x06, 0x01, 0x04,
			0x01, 0x82, 0x37, 0x15, 0x14], none},
		// from rust-asn1 test data
		OidSerializeTest{[1, 2, 840, 113549], [u8(0x06), 0x06, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d], none},
		OidSerializeTest{[1, 2, 3, 4], [u8(0x06), 0x03, 0x2a, 0x03, 0x04], none},
		OidSerializeTest{[1, 2, 840, 133549, 1, 1, 5], [u8(0x06), 0x09, 0x2a, 0x86, 0x48, 0x88,
			0x93, 0x2d, 0x01, 0x01, 0x05], none},
		OidSerializeTest{[2, 100, 3], [u8(0x06), 0x03, 0x81, 0x34, 0x03], none},
		OidSerializeTest{[1, 100, 3], [u8(0x06), 0x03, 0x81, 0x34, 0x03], error('bad oid int array')},
		OidSerializeTest{[4, 100, 3], [u8(0x06), 0x03, 0x81, 0x34, 0x03], error('bad oid int array')},
	]
	for t in td {
		// dump(t.inp)
		oid := oid_from_ints(t.inp) or {
			assert err == t.err
			continue
		}
		out := serialize_oid(oid) or {
			assert err == t.err
			continue
		}

		assert out == t.exp
		// dump(out)
		// decode back
		tag, back := decode_oid(out)!

		assert tag.number == int(TagType.oid)
		assert back == oid
	}
}

fn test_oid_encode_decode() ! {
	inp := '1.2.840.113549'

	src := new_oid_from_string(inp)!

	out := src.encode()!
	exp := [u8(0x06), 0x06, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d]

	assert out == exp

	tag, oid := decode_oid(out)!

	assert oid.str() == inp
	assert tag.number == 6
}
