// Copyright (c) 2022, 2023 blackshirt. All rights reserved.
// Use of this source code is governed by a MIT License
// that can be found in the LICENSE file.
module asn1

import arrays

// ASN.1 BIT STRING type handling
//
// The BIT STRING type denotes an arbitrary string of bits (ones and zeroes).
// A BIT STRING value can have any length, including zero. This type is a string type.
// BIT STRING, OCTET STRING, UTCTime, GeneralizedTime, and the various string types can use
// either primitive encoding or constructed encoding, at the sender’s discretion-- in BER.
// However, in DER all types that have an encoding choice between primitive and constructed
// must use the primitive encoding. DER restricts the encoding to primitive only.
// The same applies for BITSTRING. ie, For BIT STRING and OCTET STRING types,
// DER does not allow the constructed form (breaking a string into multiple TLVs) or the indefinite length form.
@[heap; noinit]
pub struct BitString {
mut:
	data []u8
	pad  u8 // numbers of unused bits
}

pub fn (bs BitString) tag() Tag {
	return Tag{.universal, false, u32(TagType.bitstring)}
}

pub fn (bs BitString) payload() ![]u8 {
	mut out := []u8{}
	out << bs.pad
	out << bs.data
	return out
}

// parse BitString using Parser
fn BitString.parse(mut p Parser) !BitString {
	bs, next := BitString.decode(p.data)!
	if next > p.data.len {
		return error('more bytes needed')
	}
	rest := if next == p.data.len { []u8{} } else { unsafe { p.data[next..] } }
	p.data = rest
	return bs
}

fn BitString.decode(bytes []u8) !(BitString, i64) {
	bs, next := BitString.decode_with_rule(bytes, .der)!
	return bs, next
}

fn BitString.decode_with_rule(bytes []u8, rule EncodingRule) !(BitString, i64) {
	tag, length_pos := Tag.decode_with_rule(bytes, 0, rule)!
	if !tag.expect(.universal, false, u32(TagType.bitstring)) {
		return error('Unexpected non-bitstring tag')
	}
	length, content_pos := Length.decode_with_rule(bytes, length_pos, rule)!
	if length < 1 {
		return error('BitString: zero length bit string')
	}
	if content_pos >= bytes.len || content_pos + length > bytes.len {
		return error('Boolean: truncated payload bytes')
	}
	payload := unsafe { bytes[content_pos..content_pos + length] }
	bs := BitString.new_with_pad(payload[1..], payload[0])!
	next := content_pos + length

	return bs, next
}

// BitString.from_binary_string creates a new BitString from binary bits arrays in s,
// ie, arrays of 1 and 0. If s.len is not multiple of 8, it would contain non-null pad,
// otherwise, the pad is null.
// Example:
// The bits string '011010001' will need two content octets: 01101000 10000000 (hexadecimal 68 80);
// seven bits of the last octet are not used and its interpreted as a pad value.
// ```v
//	bs := BitString.from_binary_string('011010001')!
// 	bs.pad == 7 and bs.data == [u8(0x68), 0x80]
// ```
fn BitString.from_binary_string(s string) !BitString {
	res, pad := parse_bits_string(s)!
	return BitString.new_with_pad(res, u8(pad))!
}

// from_string creates a new BitString from regular string s
fn BitString.from_string(s string) !BitString {
	return BitString.from_bytes(s.bytes())!
}

// from_bytes creates a new BitString from bytes array in src
fn BitString.from_bytes(src []u8) !BitString {
	return BitString.new_with_pad(src, u8(0x00))!
}

// new_with_pad creates a new BitString from bytes array in bytes with specific
// padding bits in pad
fn BitString.new_with_pad(bytes []u8, pad u8) !BitString {
	// to align with octet size, ie, 8 in length, pad bits only need maximum 7 bits
	// and when the bytes.len is multiples of 8, no need to pad, ie, pad should 0.
	if pad > 7 || (bytes.len == 0 && pad != 0) {
		return error('BitString: bad pad bits or zero length')
	}
	// this check if the pad != 0, whether the last `pad` number of bits of the last byte
	// is all bits cleared, and it was not used in the BitString data.
	if pad > 0 && (bytes[bytes.len - 1]) & ((1 << pad) - 1) != 0 {
		return error('BitString: bad args')
	}
	return BitString{
		data: bytes
		pad:  pad
	}
}

fn (bs BitString) bytes_len() int {
	return bs.data.len + 1
}

// Utility function

// maximum allowed binary bits string length
const max_bitstring_len = 8192

// valid_bitstring checks whether this s string is a valid of arrays of binary string `0` and `1`.
fn valid_bitstring(s string) bool {
	return s.contains_only('01') && s.len <= max_bitstring_len
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
