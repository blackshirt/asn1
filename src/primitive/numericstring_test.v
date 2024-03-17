// Copyright (c) 2022, 2023 blackshirt. All rights reserved.
// Use of this source code is governed by a MIT License
// that can be found in the LICENSE file.
module primitive

import asn1

fn test_encode_decode_numericstring_basic() {
	str := '98'
	exp := [u8(0x12), 0x02, 57, 56]

	ns := NumericString.from_string(str)!
	mut out := []u8{}
	ns.pack_to_asn1(mut out, .der)!
	assert out == exp

	// decode back
	nsback, _ := NumericString.unpack_from_asn1(out, 0, .der)!

	assert nsback.tag.class() == .universal
	assert nsback.tag.is_compound() == false
	assert nsback.tag.tag_number() == int(asn1.TagType.numericstring)
	assert nsback.value == str
}

struct NumericalTest {
	inp            string
	exp_length     int
	exp_bytelength []u8
	exp_values     []u8
	exp_out        []u8
	err            IError
}

fn test_encode_decode_numericstring_advanced() ! {
	// maps string to repeat
	m := {
		'1': 1
		'2': 10
		'3': 128
		'4': 256
		'5': 65536 // its too long to repeat
		//'6': 16777215
	}
	mut exp := []NumericalTest{}
	for k, v in m {
		s := k.repeat(v) // strings.repeat_string(k, v)
		b := s.bytes()
		ln := asn1.Length.from_i64(b.len)!
		mut dst := []u8{}
		ln.pack_to_asn1(mut dst, .der)!

		d := NumericalTest{
			inp: s
			exp_length: dst.len
			exp_bytelength: dst
			exp_values: b
			err: error('invalid_length_error')
		}

		exp << d
	}

	for c in exp {
		mut exp_out := [u8(asn1.TagType.numericstring)]
		exp_out << c.exp_bytelength
		exp_out << c.exp_values
		ns := NumericString.from_string(c.inp) or {
			assert err == c.err
			continue
		}
		mut out := []u8{}
		ns.pack_to_asn1(mut out, .der)!
		assert out == exp_out

		// decode back
		back, _ := NumericString.unpack_from_asn1(out, 0, .der)!

		assert back.value == c.inp
	}
}