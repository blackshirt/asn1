// Copyright (c) 2022, 2023 blackshirt. All rights reserved.
// Use of this source code is governed by a MIT License
// that can be found in the LICENSE file.
module asn1

// BITSTRING Test
//
struct BSTest {
	inp []u8
	pad u8
	out BitString
	err IError
}

fn test_new_bitstring() ! {
	ds := [
		BSTest{'abc'.bytes(), 8, BitString{}, error('BitString: bad pad bits or zero length')},
		BSTest{''.bytes(), 2, BitString{}, error('BitString: bad pad bits or zero length')},
		BSTest{[u8(0xff)], 1, BitString{}, error('BitString: bad args')},
		BSTest{[u8(0xff)], 0, BitString{
			data: [u8(0xff)]
			pad:  0
		}, none},
		BSTest{[u8(0xfe)], 0, BitString{
			data: [u8(0xfe)]
			pad:  0
		}, none},
		BSTest{[u8(0x8e)], 0, BitString{
			data: [u8(0x8e)]
			pad:  0
		}, none},
		BSTest{[u8(0x88)], 0, BitString{
			data: [u8(0x88)]
			pad:  0
		}, none},
		BSTest{[u8(0x03), 0x02, 0x00, 0x20], 0, BitString{
			data: [u8(0x03), 0x02, 0x00, 0x20]
			pad:  0
		}, none},
		BSTest{[u8(0x03), 0x02, 0x05, 0x80], 5, BitString{
			data: [u8(0x03), 0x02, 0x05, 0x80]
			pad:  5
		}, none},
	]
	for c in ds {
		out := BitString.new_with_pad(c.inp, c.pad) or {
			assert err == c.err
			continue
		}

		assert out == c.out
	}
}

struct BSParse {
	inp []u8
	src []u8
	pad u8
	err IError
}

fn test_serialize_and_decode_bitstring() ! {
	ds := [
		// from rust-asn1
		BSParse{[u8(0x03), 0x01, 0x00], ''.bytes(), 0, none},
		BSParse{[u8(0x03), 0x02, 0x07, 0x00], [u8(0)], 7, none},
		BSParse{[u8(0x03), 0x02, 0x07, 0x80], [u8(0x80)], 7, none},
		BSParse{[u8(0x03), 0x03, 0x04, 0x81, 0xf0], [u8(0x81), 0xf0], 4, none},
		BSParse{[u8(0x03), 0x00], ''.bytes(), 0, error('BitString: zero length bit string')},
		// bad length
		BSParse{[u8(0x03), 0x02, 0x07, 0x01], [u8(0x81)], 0, error('BitString: bad args')},
		// bad args
		BSParse{[u8(0x03), 0x02, 0x07, 0x40], [u8(0x81)], 0, error('BitString: bad args')},
		// bad args
		BSParse{[u8(0x03), 0x02, 0x08, 0x00], [u8(0x81)], 0, error('BitString: bad pad bits or zero length')},
		// bad args
	]
	for i, c in ds {
		bs, idx := BitString.decode(c.inp, 0) or {
			assert err == c.err
			continue
		}

		assert bs.tag.tag_number() == int(TagType.bitstring)

		// b := new_bitstring_with_pad(c.src, c.pad)!
		b := BitString.new_with_pad(c.src, c.pad)!
		// b is Encoder, so lets smart cast it to real
		assert bs == b

		// back
		mut s := []u8{}
		b.encode(mut s)!

		assert s == c.inp
	}
}

fn test_bitstring_from_bytes() ! {
	// from https://learn.microsoft.com/en-us/windows/win32/seccertenroll/about-bit-string
	data := [u8(0x03), 0x81, 0x81, 0x00, 0x47, 0xeb, 0x99, 0x5a, 0xdf, 0x9e, 0x70, 0x0d, 0xfb,
		0xa7, 0x31, 0x32, 0xc1, 0x5f, 0x5c, 0x24, 0xc2, 0xe0, 0xbf, 0xc6, 0x24, 0xaf, 0x15, 0x66,
		0x0e, 0xb8, 0x6a, 0x2e, 0xab, 0x2b, 0xc4, 0x97, 0x1f, 0xe3, 0xcb, 0xdc, 0x63, 0xa5, 0x25,
		0xec, 0xc7, 0xb4, 0x28, 0x61, 0x66, 0x36, 0xa1, 0x31, 0x1b, 0xbf, 0xdd, 0xd0, 0xfc, 0xbf,
		0x17, 0x94, 0x90, 0x1d, 0xe5, 0x5e, 0xc7, 0x11, 0x5e, 0xc9, 0x55, 0x9f, 0xeb, 0xa3, 0x3e,
		0x14, 0xc7, 0x99, 0xa6, 0xcb, 0xba, 0xa1, 0x46, 0x0f, 0x39, 0xd4, 0x44, 0xc4, 0xc8, 0x4b,
		0x76, 0x0e, 0x20, 0x5d, 0x6d, 0xa9, 0x34, 0x9e, 0xd4, 0xd5, 0x87, 0x42, 0xeb, 0x24, 0x26,
		0x51, 0x14, 0x90, 0xb4, 0x0f, 0x06, 0x5e, 0x52, 0x88, 0x32, 0x7a, 0x95, 0x20, 0xa0, 0xfd,
		0xf7, 0xe5, 0x7d, 0x60, 0xdd, 0x72, 0x68, 0x9b, 0xf5, 0x7b, 0x05, 0x8f, 0x6d, 0x1e]

	bs, idx := BitString.decode(data, 0)!

	assert bs.tag.tag_number() == int(TagType.bitstring)
	assert bs.bytes_len() == 0x81
	assert bs.pad == 0x00
}

// test for BitString from binary string
struct BinaryStringTest {
	bits string
	out  []u8
	err  IError
}

const binstring_data = [
	// empty bit string
	BinaryStringTest{'', [u8(0x03), 0x01, 0x00], none},
	// malformed bit string
	BinaryStringTest{'aaa', []u8{}, error('not valid bit string')},
	// taken examples from internet
	BinaryStringTest{'011010001', [u8(0x03), 0x03, 0x07, 0x68, 0x80], none},
	BinaryStringTest{'101100001001', [u8(0x03), 0x03, 0x04, 0xb0, 0x90], none},
	BinaryStringTest{'011011100101110111', [u8(0x03), 0x04, 0x06, 0x6e, 0x5d, 0xc0], none},
]

fn test_bitstring_from_binary_string() ! {
	for item in asn1.binstring_data {
		bs := BitString.from_binary_string(item.bits) or {
			assert err == item.err
			continue
		}
		mut out := []u8{}
		bs.encode(mut out)!
		assert out == item.out
	}
}
