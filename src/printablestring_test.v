// Copyright (c) 2022, 2023 blackshirt. All rights reserved.
// Use of this source code is governed by a MIT License
// that can be found in the LICENSE file.
module asn1

// Tests case for PrintableString
fn test_encode_printablestring_basic() ! {
	s := 'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx'
	mut buf := []u8{}
	ps := PrintableString.from_string(s)!
	ps.pack_to_asn1(mut buf)!

	mut out := [u8(0x13)]
	length := [u8(0x81), u8(s.len)]
	out << length
	out << s.bytes()
	// dump(out)
	assert out == buf

	psback, _ := PrintableString.unpack_from_asn1(buf, 0)!
	assert psback.tag.tag_number() == int(TagType.printablestring)
	assert psback.tag.class() == .universal

	assert psback.value == s
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
		ps := PrintableString.from_string(string(t.input))!
		mut out := []u8{}
		ps.pack_to_asn1(mut out)!
		// out := serialize_printablestring(string(t.input))!
		assert out == t.exp

		// decode back
		psback, _ := PrintableString.unpack_from_asn1(out, 0)!

		assert psback.value == t.input
		assert psback.tag.tag_number() == int(TagType.printablestring)
		assert psback.tag.is_constructed() == false
	}
}
