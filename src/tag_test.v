// Copyright (c) 2022, 2023 blackshirt. All rights reserved.
// Use of this source code is governed by a MIT License
// that can be found in the LICENSE file.
module asn1

struct TagLengthTest {
	number    int
	explength int
	err       IError
}

fn test_universal_class_tag_length_handling() ! {
	tags := [
		TagLengthTest{0, 1, none},
		TagLengthTest{1, 1, none},
		TagLengthTest{28, 1, none},
		TagLengthTest{0x1f, 2, none}, // 31
		TagLengthTest{0x7f, 2, none},
		TagLengthTest{128, 3, none}, // 0x80
		TagLengthTest{255, 3, none}, // 0xff
		TagLengthTest{256, 3, none},
		TagLengthTest{16380, 3, none},
		TagLengthTest{16383, 3, none}, // maximum tag number of universal class, [u8(0x1f), 0xff, 0x7f]
		TagLengthTest{16384, 4, error('TagNumber: 16384 is too big, dont exceed 16383')},
		TagLengthTest{65535, 4, error('TagNumber: 65535 is too big, dont exceed 16383')},
	]

	for i, c in tags {
		t := Tag.new(.universal, false, c.number) or {
			assert err == c.err
			continue
		}
		n := t.number.tag_number_length()
		assert n == c.explength
	}
}

struct TagUnpackTest {
	bytes       []u8
	class       TagClass
	constructed bool
	number      int
	lastpos     int
	err         IError
}

fn test_tag_unpack() ! {
	data := [
		TagUnpackTest{[u8(0x80), 0x01], .context_specific, false, 0, 1, error('TagNumber: integer is not minimally encoded')},
		TagUnpackTest{[u8(0xa0), 0x01], .context_specific, true, 0, 1, none}, //{2, 0, 1, true}},
		TagUnpackTest{[u8(0x02), 0x00], .universal, false, 2, 1, none},
		TagUnpackTest{[u8(0xfe), 0x00], .private, true, 30, 1, none},
		TagUnpackTest{[u8(0x1f), 0x1f, 0x00], .universal, false, 31, 2, none}, // high tag form
		TagUnpackTest{[u8(0x1f), 0x81, 0x00, 0x00], .universal, false, 128, 3, none},
		TagUnpackTest{[u8(0x1f), 0x81, 0x80, 0x01, 0x00], .universal, false, 16385, 4, error('TagNumber: base 128 integer too large')}, // 1x128^2 + 0x128^1 + 1x128*0
		TagUnpackTest{[u8(0x00), 0x81, 0x80], .universal, false, 0, 1, none},
		TagUnpackTest{[u8(0x00), 0x83, 0x01, 0x00], .universal, false, 0, 1, none},
		TagUnpackTest{[u8(0x1f), 0x85], .universal, false, 0, 1, error('TagNumber: truncated base 128 integer')},
		TagUnpackTest{[u8(0x1f), 0x85, 0x81], .universal, false, 0, 0, error('TagNumber: truncated base 128 integer')},
		TagUnpackTest{[u8(0x30), 0x80], .universal, true, 0x10, 1, none},
		TagUnpackTest{[u8(0xa0), 0x82, 0x00, 0xff], .context_specific, true, 0, 1, none},
	]

	for i, c in data {
		tag, pos := Tag.decode(c.bytes, 0) or {
			assert err == c.err
			continue
		}
		assert tag.class == c.class
		assert tag.constructed == c.constructed
		assert tag.number == c.number
		assert pos == c.lastpos
	}
}

struct TagAndLengthTest {
	bytes   []u8
	tag     Tag
	length  i64
	lastpos int
	err     IError
}

fn test_tagandlength_handling() ! {
	// from golang asn.1 test
	bs := [
		TagAndLengthTest{[u8(0x80), 0x01], Tag{.context_specific, false, 0}, 1, 2, none},
		TagAndLengthTest{[u8(0xa0), 0x01], Tag{.context_specific, true, 0}, 1, 2, none},
		TagAndLengthTest{[u8(0x02), 0x00], Tag{.universal, false, 2}, 0, 2, none},
		TagAndLengthTest{[u8(0xfe), 0x00], Tag{.private, true, 30}, 0, 2, none},
		TagAndLengthTest{[u8(0x1f), 0x1f, 0x00], Tag{.universal, false, 31}, 0, 3, none}, // high tag form
		TagAndLengthTest{[u8(0x1f), 0x81, 0x00, 0x01], Tag{.universal, false, 128}, 1, 4, none},
		// the last byte tells its length in long form
		TagAndLengthTest{[u8(0x1f), 0x81, 0x00, 0x81], Tag{.universal, false, 128}, 1, 4, error('Length: truncated length')},
		TagAndLengthTest{[u8(0x1f), 0x81, 0x80, 0x01, 0x00], Tag{.universal, false, 16385}, 0, 5, error('TagNumber: base 128 integer too large')}, // 1x128^2 + 0x128^1 + 1x128*0
		TagAndLengthTest{[u8(0x00), 0x81, 0x80], Tag{.universal, false, 0}, 128, 3, none},
		// need one byte length
		TagAndLengthTest{[u8(0x00), 0x83, 0x01, 0x00], Tag{.universal, false, 0}, 2, 1, error('Length: truncated length')},
		// normal version above
		TagAndLengthTest{[u8(0x00), 0x83, 0x01, 0x01, 0x01], Tag{.universal, false, 0}, 65793, 5, none}, // length = 1x256^2 + 1x256^1 + 1x256^0
		TagAndLengthTest{[u8(0x1f), 0x85], Tag{.universal, false, 0}, 0, 2, error('TagNumber: truncated base 128 integer')},
		TagAndLengthTest{[u8(0x1f), 0x85, 0x81], Tag{.universal, false, 0}, 0, 0, error('TagNumber: truncated base 128 integer')},
		// this last bytes tell the length is in undefinite length, 0x80
		TagAndLengthTest{[u8(0x30), 0x80], Tag{.universal, true, 0x10}, 0, 2, error('Length: unsupported undefinite length')},
		// still truncated length part
		TagAndLengthTest{[u8(0x30), 0x81], Tag{.universal, true, 0x10}, 0, 2, error('Length: truncated length')},
		// still in uneeded form of length
		TagAndLengthTest{[u8(0x30), 0x81, 0x01], Tag{.universal, true, 0x10}, 1, 3, error('Length: dont needed in long form')},
		// its fullfill the der requirement
		TagAndLengthTest{[u8(0x30), 0x81, 0x80], Tag{.universal, true, 0x10}, 128, 3, none},
		// this tell two bytes of length contains leading spurious zero's
		TagAndLengthTest{[u8(0xa0), 0x82, 0x00, 0xff], Tag{.context_specific, true, 0}, 255, 1, error('Length: leading zeros')},
		TagAndLengthTest{[u8(0xa0), 0x82, 0x01, 0xff], Tag{.context_specific, true, 0}, 511, 4, none},
		// Superfluous zeros in the length should be an error.
		TagAndLengthTest{[u8(0xa0), 0x82, 0x00, 0xff], Tag{.context_specific, true, 0}, 0, 4, error('Length: leading zeros')}, //{}},
		// Lengths up to the maximum size of an int should work.
		TagAndLengthTest{[u8(0xa0), 0x84, 0x7f, 0xff, 0xff, 0xff], Tag{.context_specific, true, 0}, 0x7fffffff, 6, none}, //{2, 0, 0x7fffffff, true}},
		// Lengths that would overflow an int should be rejected.
		TagAndLengthTest{[u8(0xa0), 0x84, 0x80, 0x00, 0x00, 0x00], Tag{.context_specific, true, 0}, 2147483648, 6, none}, //{}},
		// Long length form may not be used for lengths that fit in short form.
		TagAndLengthTest{[u8(0xa0), 0x81, 0x7f], Tag{.context_specific, true, 0}, 0, 0, error('Length: dont needed in long form')}, //{}},
		// Tag numbers which would overflow int32 are rejected. (The number below is 2^31.)
		TagAndLengthTest{[u8(0x1f), 0x88, 0x80, 0x80, 0x80, 0x00, 0x00], Tag{.universal, false, 0}, 0, 0, error('TagNumber: negative number')}, //{}},
		// Tag numbers that fit in an int32 are valid. (The number below is 2^31 - 1.) but its bigger than max_tag_bytes_length
		TagAndLengthTest{[u8(0x1f), 0x87, 0xFF, 0xFF, 0xFF, 0x7F, 0x00], Tag{.universal, false, 2147483647}, 0, 7, error('TagNumber: base 128 integer too large')},
		// Long tag number form may not be used for tags that fit in short form.
		TagAndLengthTest{[u8(0x1f), 0x1e, 0x00], Tag{.universal, false, 0}, 0, 0, error('Tag: non-minimal tag')}, //{}},
	]

	for i, c in bs {
		tag, pos := Tag.decode(c.bytes, 0) or {
			assert err == c.err
			continue
		}
		assert tag == c.tag

		length, idx := Length.decode(c.bytes, pos) or {
			assert err == c.err
			continue
		}

		assert length == c.length
		assert idx == c.lastpos
	}
}

struct TagNumberTest {
	num         int
	class       TagClass
	constructed bool
	exp         []u8
	err         IError
}

fn test_serialize_tag() ! {
	data := [
		TagNumberTest{0, .universal, false, [u8(0x00)], none},
		TagNumberTest{32, .universal, false, [u8(0x1f), 0x20], none}, // multibyte tag: 0x1f 0x20
		TagNumberTest{255, .universal, false, [u8(0x1f), 0x81, 0x7f], none}, // multibyte tag: 0x1f 0x81 0x7f
		TagNumberTest{0, .universal, true, [u8(0x20)], none}, // bits 6 set, 0010 0000 == 32
		TagNumberTest{1, .universal, true, [u8(0x21)], none}, // bits 6 set, 0010 0001 == 31
		TagNumberTest{32, .universal, true, [u8(0x3f), 0x20], none}, // multibyte tag: 00111111 0x20
		TagNumberTest{32, .application, true, [u8(0x7f), 0x20], none}, // multibyte tag: 127 (01111111) 0x20
		TagNumberTest{32, .context_specific, true, [u8(0xbf), 0x20], none}, // multibyte tag: 197 (10111111) 0x20
		TagNumberTest{32, .private, true, [u8(0xff), 0x20], none}, // multibyte tag: 255 (11111111) 0x20
		TagNumberTest{255, .context_specific, true, [u8(0xbf), 0x81, 0x7f], none}, // multibyte tag: 0xbf 0x81 0x7f
		TagNumberTest{255, .context_specific, false, [u8(0x9f), 0x81, 0x7f], none}, // multibyte tag: 0xbf 0x81 0x7f
		TagNumberTest{16383, .universal, false, [u8(0x1f), 0xff, 0x7f], none}, // multibyte tag: 0x1f 0xff 0x7f
		// overflow max_tag_value
		TagNumberTest{16385, .universal, false, [u8(0x1f), 0xff, 0x7f], error('TagNumber: 16385 is too big, dont exceed 16383')}, // multibyte tag: 0x1f 0xff 0x7f
	]

	for c in data {
		mut dst := []u8{}
		tag := Tag.new(c.class, c.constructed, c.num) or {
			assert err == c.err
			continue
		}
		tag.encode(mut dst)!
		assert dst == c.exp
	}
}
