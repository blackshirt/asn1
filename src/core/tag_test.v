// Copyright (c) 2022, 2023 blackshirt. All rights reserved.
// Use of this source code is governed by a MIT License
// that can be found in the LICENSE file.
module asn1

struct TagTest {
	value 		int
	compound 	bool
	expected 	int
	err 		IError
}

fn test_universal_class_tag_handling() ! {
	tags := [
		TagTest{0, false, 1},
		TagTest{1, false, 1},
		TagTest{28, false, 1},
		TagTest{0x1f, false, 2}, // 31
		TagTest{0x1f, true, 2}, // 31
		TagTest{0x7f, false, 2},
		TagTest{128, false, 3}, // 0x80
		TagTest{255, false, 3}, // 0xff
		TagTest{256, true, 3},
		TagTest{16384, false, 4},
		TagTest{16385, false, 4},
		TagTest{65535, true, 4},
		TagTest{65535, false, 4}, // 0xffff
		TagTest{65536, true, 4},
		TagTest{65536, false, 4},
		TagTest{65537, true, 4},
		TagTest{65537, false, 4},
		TagTest{16777214, false, 5},
		TagTest{16777215, true, 5}, // 0x00ffffff
		TagTest{16777216, true, 5},
		TagTest{16777217, false, 5},
	]

	for i, c in tags {
		t := new_tag(.universal, c.compound, c.value)!
		v := TagValue.from(c.value)!
		n := v.bytes_needed()
		mut dst := []u8{}
		t.pack(mut dst)
		
		// assert length as expected
		assert n == c.expected
		// assert lenggth of serialized tag as expected
		assert dst.len == c.expected

		// read bytes back to tag
		tag, offset := Tag.unpack(dst, 0)!
		assert tag == t
		assert offset == n
	}
}

/*
struct TagReadTest {
	value         []u8
	class       Class
	constructed bool
	number      int
	lastpos     int
	err         IError
}

fn test_read_tag() ! {
	data := [
		TagReadTest{[u8(0x80), 0x01], .context, false, 0, 1, error('integer is not minimaly encoded')},
		TagReadTest{[u8(0xa0), 0x01], .context, true, 0, 1, none}, //{2, 0, 1, true}},
		TagReadTest{[u8(0x02), 0x00], .universal, false, 2, 1, none},
		TagReadTest{[u8(0xfe), 0x00], .private, true, 30, 1, none},
		TagReadTest{[u8(0x1f), 0x1f, 0x00], .universal, false, 31, 2, none}, // high tag form
		TagReadTest{[u8(0x1f), 0x81, 0x00, 0x00], .universal, false, 128, 3, none},
		TagReadTest{[u8(0x1f), 0x81, 0x80, 0x01, 0x00], .universal, false, 16385, 4, none}, // 1x128^2 + 0x128^1 + 1x128*0
		TagReadTest{[u8(0x00), 0x81, 0x80], .universal, false, 0, 1, none},
		TagReadTest{[u8(0x00), 0x83, 0x01, 0x00], .universal, false, 0, 1, none},
		TagReadTest{[u8(0x1f), 0x85], .universal, false, 0, 1, error('truncated base 128 integer')},
		TagReadTest{[u8(0x1f), 0x85, 0x81], .universal, false, 0, 0, error('truncated base 128 integer')},
		TagReadTest{[u8(0x30), 0x80], .universal, true, 0x10, 1, none},
		TagReadTest{[u8(0xa0), 0x82, 0x00, 0xff], .context, true, 0, 1, none},
	]

	for c in data {
		tag, pos := read_tag(c.value, 0) or {
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
	value     []u8
	tag     Tag
	length  int
	lastpos int
	err     IError
}

fn test_tagandlength_handling() ! {
	// from golang asn.1 test
	bs := [
		TagAndLengthTest{[u8(0x80), 0x01], Tag{.context, false, 0}, 1, 2, none},
		TagAndLengthTest{[u8(0xa0), 0x01], Tag{.context, true, 0}, 1, 2, none},
		TagAndLengthTest{[u8(0x02), 0x00], Tag{.universal, false, 2}, 0, 2, none},
		TagAndLengthTest{[u8(0xfe), 0x00], Tag{.private, true, 30}, 0, 2, none},
		TagAndLengthTest{[u8(0x1f), 0x1f, 0x00], Tag{.universal, false, 31}, 0, 3, none}, // high tag form
		TagAndLengthTest{[u8(0x1f), 0x81, 0x00, 0x01], Tag{.universal, false, 128}, 1, 4, none},
		// the last byte tells its length in long form
		TagAndLengthTest{[u8(0x1f), 0x81, 0x00, 0x81], Tag{.universal, false, 128}, 1, 4, error('truncated tag or length')},
		TagAndLengthTest{[u8(0x1f), 0x81, 0x80, 0x01, 0x00], Tag{.universal, false, 16385}, 0, 5, none}, // 1x128^2 + 0x128^1 + 1x128*0
		TagAndLengthTest{[u8(0x00), 0x81, 0x80], Tag{.universal, false, 0}, 128, 3, none},
		// need one byte length
		TagAndLengthTest{[u8(0x00), 0x83, 0x01, 0x00], Tag{.universal, false, 0}, 2, 1, error('truncated tag or length')},
		// normal version above
		TagAndLengthTest{[u8(0x00), 0x83, 0x01, 0x01, 0x01], Tag{.universal, false, 0}, 65793, 5, none}, // length = 1x256^2 + 1x256^1 + 1x256^0
		TagAndLengthTest{[u8(0x1f), 0x85], Tag{.universal, false, 0}, 0, 2, error('truncated base 128 integer')},
		TagAndLengthTest{[u8(0x1f), 0x85, 0x81], Tag{.universal, false, 0}, 0, 0, error('truncated base 128 integer')},
		// this last bytes tell the length is in undefinite length, 0x80
		TagAndLengthTest{[u8(0x30), 0x80], Tag{.universal, true, 0x10}, 0, 2, error('unsupported undefinite length')},
		// still truncated length part
		TagAndLengthTest{[u8(0x30), 0x81], Tag{.universal, true, 0x10}, 0, 2, error('truncated tag or length')},
		// still in uneeded form of length
		TagAndLengthTest{[u8(0x30), 0x81, 0x01], Tag{.universal, true, 0x10}, 1, 3, error('dont needed in long form')},
		// its fullfill the der requirement
		TagAndLengthTest{[u8(0x30), 0x81, 0x80], Tag{.universal, true, 0x10}, 128, 3, none},
		// this tell two bytes of length contains leading spurious zero's
		TagAndLengthTest{[u8(0xa0), 0x82, 0x00, 0xff], Tag{.context, true, 0}, 255, 1, error('leading zeros')},
		TagAndLengthTest{[u8(0xa0), 0x82, 0x01, 0xff], Tag{.context, true, 0}, 511, 4, none},
		// Superfluous zeros in the length should be an error.
		TagAndLengthTest{[u8(0xa0), 0x82, 0x00, 0xff], Tag{.context, true, 0}, 0, 4, error('leading zeros')}, //{}},
		// Lengths up to the maximum size of an int should work.
		TagAndLengthTest{[u8(0xa0), 0x84, 0x7f, 0xff, 0xff, 0xff], Tag{.context, true, 0}, 0x7fffffff, 6, none}, //{2, 0, 0x7fffffff, true}},
		// Lengths that would overflow an int should be rejected.
		TagAndLengthTest{[u8(0xa0), 0x84, 0x80, 0x00, 0x00, 0x00], Tag{.context, true, 0}, 0, 4, error('integer overflow')}, //{}},
		// Long length form may not be used for lengths that fit in short form.
		TagAndLengthTest{[u8(0xa0), 0x81, 0x7f], Tag{.context, true, 0}, 0, 0, error('dont needed in long form')}, //{}},
		// Tag numbers which would overflow int32 are rejected. (The value below is 2^31.)
		TagAndLengthTest{[u8(0x1f), 0x88, 0x80, 0x80, 0x80, 0x00, 0x00], Tag{.universal, false, 0}, 0, 0, error('base 128 integer too large')}, //{}},
		// Tag numbers that fit in an int32 are valid. (The value below is 2^31 - 1.) but its bigger than max_tag_bytes_length
		TagAndLengthTest{[u8(0x1f), 0x87, 0xFF, 0xFF, 0xFF, 0x7F, 0x00], Tag{.universal, false, 2147483647}, 0, 7, error('tag bytes is too big')},
		// Long tag number form may not be used for tags that fit in short form.
		TagAndLengthTest{[u8(0x1f), 0x1e, 0x00], Tag{.universal, false, 0}, 0, 0, error('non-minimal tag')}, //{}},
	]

	for _, c in bs {
		tag, pos := read_tag(c.value, 0) or {
			assert err == c.err
			continue
		}
		assert tag == c.tag

		length, idx := decode_length(c.value, pos) or {
			assert err == c.err
			continue
		}

		assert length == c.length
		assert idx == c.lastpos
	}
}

struct TagNum {
	num      int
	class    Class
	compound bool
	exp      []u8
	err      IError
}

fn test_serialize_tag() {
	data := [
		TagNum{0, .universal, false, [u8(0x00)], none},
		TagNum{32, .universal, false, [u8(0x1f), 0x20], none}, // multibyte tag: 0x1f 0x20
		TagNum{255, .universal, false, [u8(0x1f), 0x81, 0x7f], none}, // multibyte tag: 0x1f 0x81 0x7f
		TagNum{0, .universal, true, [u8(0x20)], none}, // bits 6 set, 0010 0000 == 32
		TagNum{1, .universal, true, [u8(0x21)], none}, // bits 6 set, 0010 0001 == 31
		TagNum{32, .universal, true, [u8(0x3f), 0x20], none}, // multibyte tag: 00111111 0x20
		TagNum{32, .application, true, [u8(0x7f), 0x20], none}, // multibyte tag: 127 (01111111) 0x20
		TagNum{32, .context, true, [u8(0xbf), 0x20], none}, // multibyte tag: 197 (10111111) 0x20
		TagNum{32, .private, true, [u8(0xff), 0x20], none}, // multibyte tag: 255 (11111111) 0x20
		TagNum{255, .context, true, [u8(0xbf), 0x81, 0x7f], none}, // multibyte tag: 0xbf 0x81 0x7f
		TagNum{255, .context, false, [u8(0x9f), 0x81, 0x7f], none}, // multibyte tag: 0xbf 0x81 0x7f
	]

	for c in data {
		mut dst := []u8{}
		t1 := new_tag(c.class, c.compound, c.num)
		serialize_tag(mut dst, t1)
		assert dst == c.exp
	}
}

fn test_overflow_max_tag_bytes_length() ! {
	// its should overflow the limit of max_tag_bytes_length
	data := [u8(0x1f), 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f]
	tag, _ := read_tag(data, 0) or {
		assert err == error('base 128 integer too large')
		return
	}
}

fn test_max_tag_bytes_length() ! {
	// its should overflow the limit of max_tag_bytes_length
	data := [u8(0x1f), 0xff, 0xff, 0xff, 0x7f]
	tag, _ := read_tag(data, 0)!
	assert tag.class == .universal
	assert tag.constructed == false
	assert tag.number == 268435455
}

// ASN.1 Test Suite from https://github.com/YuryStrozhevsky/asn1-test-suite
fn test_tc1_tag_too_long() ! {
	value := [u8(0x9f), 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f, 0x01, 0x40]

	_, _ := read_tag(value, 0) or {
		assert err == error('tag bytes is too big')
		return
	}
}

fn test_tc2_never_ending_tagnumber() ! {
	value := []u8{}
	_, _ := read_tag(value, 0) or {
		assert err == error('get ${value.len} bytes for reading tag, its not enough')
		return
	}
}

*/