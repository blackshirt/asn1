// Copyright (c) 2022, 2023 blackshirt. All rights reserved.
// Use of this source code is governed by a MIT License
// that can be found in the LICENSE file.
module asn1

struct IA5StringTest {
	s   string
	out []u8
	err IError
}

fn test_ia5string_handling() ! {
	data := [
		IA5StringTest{'test', [u8(22), 4, 116, 101, 115, 116], none},
		IA5StringTest{'abc', '\x16\x03abc'.bytes(), none},
		IA5StringTest{`🚀`.str(), []u8{}, error('IA5String: contains non-ascii chars')},
		IA5StringTest{')', '\x16\x01)'.bytes(), none},
		IA5StringTest{'\x13\x03ab\x00', []u8{}, error('IA5String: contains non-ascii chars')},
	]

	for c in data {
		s := IA5String.new(c.s) or {
			assert err == c.err
			continue
		}
		mut out := []u8{}
		s.pack_to_asn1(mut out) or {
			assert err == c.err
			continue
		}
		assert out == c.out

		// unpack back
		ret, next := IA5String.unpack_from_asn1(out, 0) or {
			assert err == c.err
			continue
		}

		assert ret.tag.tag_number() == 22
		assert ret.tag.class() == Class.universal
		assert ret.tag.is_compound() == false
		assert ret.value == c.s
	}
}
