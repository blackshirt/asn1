// Copyright (c) 2022, 2023 blackshirt. All rights reserved.
// Use of this source code is governed by a MIT License
// that can be found in the LICENSE file.
module core

// ASN.1 length handling routines.
//
// The standard of X.690 ITU document defines two length types - definite and indefinite.
// DER encoding only uses the definite length.
// There are two forms of definite length octets: short (for lengths between 0 and 127),
// and long definite (for lengths between 0 and 2^1008 -1).
// Short form. One octet. Bit 8 has value "0" and bits 7-1 give the length.
// Long form. Two to 127 octets. Bit 8 of first octet has value "1" and bits 7-1 give
// the number of additional length octets. 
// Second and following octets give the length, base 256, most significant digit first.
//
// This mpdule only support definite length, in short or long form. Its required for DER encoding
// the length octets should in definite length.

const max_definite_length = 126 // in bytes, 1008:8
// TODO: represent it in 'big.Integer'
// const max_ber_length = (1<<1008)-1

type Length = int

// bytes_needed tells how many bytes to represent this length 
fn (v Length) bytes_needed() int {
	mut i := v
	mut num := 1
	for i > 255 {
		num++
		i >>= 8
	}
	return num
}

		
// pack_and_append packs v to bytes and apends it to `to`
fn (v Length) pack_and_append(mut to []u8) {
	mut n := v.bytes_needed()
	for ; n > 0; n-- {
		to << u8(i >> (n - 1) * 8)
	}
}


// length calculates the length of bytes length 
fn (v Length) length() int {
	mut len := 1
	if v >= 128 {
		n := v.bytes_needed()
		len += n
	}
	return len
}

// pack serializes Length v into bytes and append it into `to` 
fn (v Length) pack(mut to []u8) ! {
	// Long form 
	if v >= 128 {
		length := v.bytes_needed()
		// if the length overflow the limit, something bad happen
		// return error instead
		if length > max_definite_length {
			return error("something bad in your length")
		}
		to << 0x80 | u8(length)
		length.pack_and_append(mut to)
	} else {
		// short form
		to << u8(v)
	}
}

// unpack deserializes back of buffer into Length form, start from offset loc in the buf.
// Its return Length and next offset in the buffer buf to process on, and return error if fail.
fn Length.unpack(buf []u8, loc int) !(Length, int) {
	mut pos := loc
	if pos >= buf.len {
		return error('Length: truncated length')
	}
	mut b := buf[pos]
	pos += 1
	mut length := 0
	// check for the most bit is set or not 
	if b & 0x80 == 0 {
		// for lengths between 0 and 127, the one-octet short form can be used. 
		// The bit 7 of the length octet is set to 0, and the length is encoded 
		// as an unsigned binary value in the octet's rightmost seven bits.
		length = int(b & 0x7f)
	} else {
		// Otherwise, its a Long definite form or undefinite form 
		num_bytes := b & 0x7f
		if num_bytes == 0 {
			// TODO: add support for undefinite length 
			return error('Length: unsupported undefinite length')
		}

		for i := 0; i < num_bytes; i++ {
			if pos >= buf.len {
				return error('Length: truncated length')
			}
			b = buf[pos]
			pos += 1
			if length > (max_i64 >> 8) {
				return error('Length: integer overflow')
			}
			length <<= 8
			length |= int(b)
			if length == 0 {
				// TODO: leading zeros is allowed in Long form of BER encoding, but 
				// not allowed in DER encoding
				return error('Length: leading zeros')
			}
		}

		// do not allow values < 0x80 to be encoded in long form
		if length < 0x80 {
			// TODO: allow in BER 
			return error('Length: dont needed in long form')
		}
	}
	return Length(length), pos
}
