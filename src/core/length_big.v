module core

import math.big

// experimental ASN.1 length handling with support from `big.Integer`

type Asn1Length = big.Integer

fn (v Asn1Length) bytes_needed() int {
	nbits := v.bit_len()
	if nbits % 8 == 0 { return nbits/8 }
	return nbits/8 + 1
}
	
fn (v Asn1Length) total_length() int {
	mut len := 1
	if v >= big128 {
		n := v.bytes_needed()
		len += n
	}
	return len
}
		
fn (v Asn1Length) pack(mut to []u8) ! {
	bytes, _ := v.bytes()
	if bytes.len > max_definite_length {
		return error("big: bytes len exceed limit")
	}
	// Long form
	if v >= big128 {
		to << 0x80 | u8(bytes.len)
		to << bytes
	} else {
		// short form
		to << bytes
	}
}
	
