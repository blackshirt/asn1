// Copyright (c) 2022, 2023 blackshirt. All rights reserved.
// Use of this source code is governed by a MIT License
// that can be found in the LICENSE file.
module asn1

fn test_encode_decode_numericstring_basic() {
	str := '98'
	exp := [u8(0x12), 0x02, 57, 56]

	out := serialize_numericstring(str)!
	assert out == exp

	// decode back
	tag, sout := decode_numericstring(out)!

	assert tag.class == .universal
	assert tag.constructed == false
	assert tag.number == int(TagType.numericstring)
	assert str == sout
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
		l := b.len
		mut dst := []u8{}
		serialize_length(mut dst, l)

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
		mut exp_out := [u8(TagType.numericstring)]
		exp_out << c.exp_bytelength
		exp_out << c.exp_values
		out := serialize_numericstring(c.inp) or {
			assert err == c.err
			continue
		}
		assert out == exp_out

		// decode back
		tag, back := decode_numericstring(out)!

		assert back == c.inp
	}
}
