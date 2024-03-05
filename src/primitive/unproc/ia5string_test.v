// Copyright (c) 2022, 2023 blackshirt. All rights reserved.
// Use of this source code is governed by a MIT License
// that can be found in the LICENSE file.
module asn1

struct IA5StringTest {
	s   string
	out []u8
	err IError
}

fn test_ia58string_handling() ! {
	data := [
		IA5StringTest{'test', [u8(22), 4, 116, 101, 115, 116], none},
		IA5StringTest{'abc', '\x16\x03abc'.bytes(), none},
		IA5StringTest{`🚀`.str(), []u8{}, error('contains invalid char')},
		IA5StringTest{')', '\x16\x01)'.bytes(), none},
		IA5StringTest{'\x13\x03ab\x00', []u8{}, error('contains invalid char')},
	]

	for c in data {
		out := serialize_ia5string(c.s) or {
			assert err == c.err
			continue
		}
		assert out == c.out

		tag, back := decode_ia5string(out)!

		assert tag.number == int(TagType.ia5string)
		assert back == c.s
	}
}
