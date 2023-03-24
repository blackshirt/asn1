// Copyright (c) 2022, 2023 blackshirt. All rights reserved.
// Use of this source code is governed by a MIT License
// that can be found in the LICENSE file.
module asn1

// Tests case for PrintableString
fn test_encode_printablestring_basic() ! {
	s := 'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx'
	mut buf := []u8{}
	buf << u8(0x13)
	serialize_length(mut buf, s.len)
	buf << s.bytes()
	out := serialize_printablestring(s)!

	// dump(out)
	assert out == buf

	tag, str := decode_printablestring(out)!
	assert tag.number == int(TagType.printablestring)
	assert tag.class == .universal

	assert str == s
}

struct EncodingTest[T] {
	input T
	exp   []u8
}

fn test_encode_printablestring_generic() {
	data := [
		// from dart asn1lib test
		EncodingTest[string]{'TheTestString', [u8(0x13), 13, 84, 104, 101, 84, 101, 115, 116, 83,
			116, 114, 105, 110, 103]},
		EncodingTest[string]{'Test User 1', [u8(0x13), 0x0b, 84, 101, 115, 116, 32, 85, 115, 101,
			114, 32, 49]},
	]

	for t in data {
		out := serialize_printablestring(string(t.input))!
		assert out == t.exp

		// decode back
		tag, str := decode_printablestring(out)!

		assert str == t.input
		assert tag.number == int(TagType.printablestring)
		assert tag.constructed == false
	}
}
