// Copyright (c) 2022, 2023 blackshirt. All rights reserved.
// Use of this source code is governed by a MIT License
// that can be found in the LICENSE file.
module asn1

import arrays

// ASN.1 BIT STRING type handling
// The BIT STRING type denotes an arbitrary string of bits (ones and zeroes).
// A BIT STRING value can have any length, including zero. This type is a string type.
pub struct BitString {
	tag  Tag = Tag{.universal, false, int(TagType.bitstring)}
	data []u8
	pad  u8 // numbers of unused bits
}

// BitString.from_binary_string creates a new BitString from binary bits arrays in s,
// ie, arrays of `1` and `0`. If s.len is not multiple of 8, it would contain non-null pad,
// otherwise, the pad is null.
// Example:
// The bits string '011010001' will need two content octets: 01101000 10000000 (hexadecimal 68 80);
// seven bits of the last octet are not used and its interpreted as a pad value.
// bs := BitString.from_binary_string('011010001')!
// bs.pad == 7 and bs.data == [u8(0x68), 0x80]
pub fn BitString.from_binary_string(s string, p Params) !BitString {
	res, pad := parse_bits_string(s)!
	return BitString.new_with_pad(res, u8(pad), p)!
}

// from_string creates a new BitString from regular string s
pub fn BitString.from_string(s string, p Params) !BitString {
	return BitString.from_bytes(s.bytes(), p)
}

// from_bytes creates a new BitString from bytes array in src
pub fn BitString.from_bytes(src []u8, p Params) !BitString {
	return BitString.new_with_pad(src, u8(0x00), p)!
}

// new_with_pad creates a new BitString from bytes array in src with specific
// padding bits in pad
fn BitString.new_with_pad(src []u8, pad u8, p Params) !BitString {
	// to align with octet size, ie, 8 in length, pad bits only need maximum 7 bits
	// and when the bytes.len is multiples of 8, no need to pad, ie, pad should 0.
	if pad > 7 || (src.len == 0 && pad != 0) {
		return error('BitString: bad pad bits or zero length')
	}
	// this check if the pad != 0, whether the last `pad` number of bits of the last byte
	// is all bits cleared, and it was not used in the BitString data.
	if pad > 0 && (src[src.len - 1]) & ((1 << pad) - 1) != 0 {
		return error('BitString: bad args')
	}
	return BitString{
		data: src
		pad: pad
	}
}

fn (bs BitString) bytes_len() int {
	return bs.data.len + 1
}

pub fn (b BitString) tag() Tag {
	return b.tag
}

pub fn (bs BitString) payload(p Params) ![]u8 {
	mut out := []u8{}
	out << bs.pad
	out << bs.data
	return out
}

pub fn (bs BitString) length(p Params) !int {
	return bs.bytes_len()
}

pub fn (bs BitString) packed_length(p Params) !int {
	mut n := 0

	n += bs.tag.packed_length(p)!
	len := bs.length(p)!
	bslen := Length.from_i64(len)!
	n += bslen.packed_length(p)!
	n += len

	return n
}

pub fn (bs BitString) encode(mut dst []u8, p Params) ! {
	// we currently only support .der and (stricter) .ber
	if p.mode != .der && p.mode != .ber {
		return error('BitString: unsupported mode')
	}

	bs.tag.encode(mut dst, p)!
	length := Length.from_i64(bs.bytes_len())!
	length.encode(mut dst, p)!

	// write pad bit and data
	dst << bs.pad
	dst << bs.data
}

pub fn BitString.decode(src []u8, loc i64, p Params) !(BitString, i64) {
	raw, next := RawElement.decode(src, loc, p)!

	if raw.tag.tag_class() != .universal || raw.tag.is_constructed()
		|| raw.tag.tag_number() != int(TagType.bitstring) {
		return error('BitString: bad tag check')
	}

	// check for length and required bytes
	if raw.payload.len == 0 {
		return error('BitString: zero length bit string')
	}

	bs := BitString.new_with_pad(raw.payload[1..], raw.payload[0], p)!
	return bs, next
}

// Utility function

// maximum allowed binary bits string length
const max_bitstring_len = 8192

// valid_bitstring checks whether this s string is a valid of arrays of binary string `0` and `1`.
fn valid_bitstring(s string) bool {
	return s.contains_only('01') && s.len <= asn1.max_bitstring_len
}

// parse_into_u8 parses arrays of binary bits of `0` and '1' with length == 8 into single byte (u8)
// Example: parse_to_u8('01101000')! == u8(0x68) // => true
fn parse_into_u8(s string) !u8 {
	if s.len != 8 {
		return error('not 8 length')
	}
	if !valid_bitstring(s) {
		return error('not valid bit string: ${s}')
	}
	mut b := u8(0)

	mut ctr := 0
	bitmask := 0x01
	for bit := 0; bit < s.len; bit++ {
		v := u32(s[ctr] & bitmask) << (7 - bit)
		b |= u8(v & 0x00ff)
		ctr += 1
	}
	return b
}

// pad_into_octet pads string s by string `0` into new string with size 8
fn pad_into_octet(s string) !string {
	if valid_bitstring(s) && s.len > 0 && s.len < 8 {
		len := if s.len % 8 == 0 { 0 } else { 8 - s.len % 8 }
		pad := '0'.repeat(len)
		res := s + pad
		return res
	}
	return error('not valid bit string')
}

// parse_bits_string parses binary bits string s into arrays of byte and number of padding bits
fn parse_bits_string(s string) !([]u8, int) {
	if s.len == 0 {
		return []u8{}, 0
	}
	if !valid_bitstring(s) {
		return error('not valid bit string')
	}
	arr := arrays.chunk[u8](s.bytes(), 8)
	mut res := []u8{}
	pad_len := if s.len % 8 == 0 { 0 } else { 8 - s.len % 8 }
	if pad_len > 7 {
		return error('pad_len > 7')
	}
	for item in arr {
		if item.len != 8 {
			bts := pad_into_octet(item.bytestr())!
			val := parse_into_u8(bts)!
			res << val
		}
		if item.len == 8 {
			b := parse_into_u8(item.bytestr())!
			res << b
		}
	}
	return res, pad_len
}
