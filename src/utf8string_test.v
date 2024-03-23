// Copyright (c) 2022, 2023 blackshirt. All rights reserved.
// Use of this source code is governed by a MIT License
// that can be found in the LICENSE file.
module asn1

// UTFString test
struct UTF8StringTest {
	s   string
	out []u8
	err IError
}

fn test_uf8string_handling() ! {
	data := [
		UTF8StringTest{'test', [u8(12), 4, 116, 101, 115, 116], none},
		UTF8StringTest{'abc', '\x0c\x03abc'.bytes(), none},
		// rocket := `🚀` was rune, single unicode, rocket.bytes() = [240, 159, 154, 128]
		UTF8StringTest{`🚀`.str(), [u8(12), 4, 240, 159, 154, 128], none},
		UTF8StringTest{')', '\x0c\x01)'.bytes(), none},
		UTF8StringTest{'\x13\x03ab\x00', [u8(12), 5, 19, 3, 97, 98, 0], none},
		UTF8StringTest{'Test User 1', '\x0c\x0bTest User 1'.bytes(), none},
		// invalid utf8 string, emoji with removed first and fifth byte
		UTF8StringTest{'🐶🐶🐶🚀'.substr(0, 5), []u8{}, error('UTF8String: invalid UTF-8 string')},
	]

	for c in data {
		us := UTF8String.from_string(c.s) or {
			assert err == c.err
			continue
		}
		mut out := []u8{}
		us.encode(mut out) or {
			assert err == c.err
			continue
		}
		assert out == c.out

		uss, _ := UTF8String.decode(out, 0)!

		assert uss.tag.tag_number() == int(TagType.utf8string)
		assert uss.value == c.s
	}
}
