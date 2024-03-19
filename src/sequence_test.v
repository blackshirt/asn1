// Copyright (c) 2022, 2023 blackshirt. All rights reserved.
// Use of this source code is governed by a MIT License
// that can be found in the LICENSE file.
module asn1

import math
import math.big

fn test_sequence_contains_other_seq() ! {
	// lets create first sequence
	mut seq1 := Sequence.new(false)!
	// add two primitive elements to the sequence
	seq1.add_element(Boolean.new(true))
	seq1.add_element(Null.new())
	seq1.add_element(Boolean.new(false))

	// lets create another sequences, where it contains primitive element and first sequence created above.
	mut seq2 := Sequence.new(false)!
	seq2.add_element(Boolean.new(false))
	seq2.add_element(seq1)
	seq2.add_element(Boolean.new(true))

	// lets serialize it to bytes
	mut out := []u8{}
	seq2.pack_to_asn1(mut out)!
	expected := [u8(0x30), 16, u8(0x01), 0x01, 0x00, u8(0x30), 8, 0x01, 0x01, 0xff, u8(0x05), 0x00,
		u8(0x01), 0x01, 0x00, u8(0x01), 0x01, 0xff]
	// assert for right value
	assert seq2.length() == 16
	assert seq2.packed_length() == 18
	assert out == expected
}

/*
fn test_sequence_der_decode() ! {
	data := [u8(0x30), 16, u8(0x01), 0x01, 0x00, u8(0x30), 8, u8(0x01), 0x01, 0xff, u8(0x05), 0x00,
		u8(0x01), 0x01, 0x00, u8(0x01), 0x01, 0xff]
	out := der_decode(data)!
	// lets cast it to sequence
	seq := out.as_sequence()!

	el0 := seq.elements[0].as_boolean()!
	assert el0 == Boolean(false)

	el1 := seq.elements[1].as_sequence()!
	assert el1.elements.len == 3 // [boolean(true), null, boolean(false)]
	// dump(el1)
	el2 := seq.elements[2].as_boolean()!
	assert el2 == Boolean(true)
}

fn test_sequence_add_and_encode_boolean() {
	o1 := new_boolean(false)
	o2 := new_boolean(true)
	o3 := new_boolean(true)
	mut seq := new_sequence()
	seq.add(o1)
	seq.add(o2)
	seq.add(o3)

	length := seq.length()
	assert length == 9

	size := seq.size()
	assert size == 11

	out := seq.encode()!

	exp := [u8(0x30), 0x09, 0x01, 0x01, 0x00, 0x01, 0x01, 0xff, 0x01, 0x01, 0xff]

	assert out == exp
	assert exp.len == size

	back := decode_sequence(out)!

	assert back.elements.len == 3

	assert back.tag.number == 0x10
	assert back.tag.constructed == true
	assert back.tag.class == .universal

	assert back.elements[0].tag().class == .universal
	assert back.elements[0].tag().constructed == false
	assert back.elements[0].tag().number == 0x01

	assert back.elements[1].tag().class == .universal
	assert back.elements[1].tag().constructed == false
	assert back.elements[1].tag().number == 0x01

	assert back.elements[2].tag().number == 0x01
	assert back.elements[2].tag().constructed == false
}

fn test_sequence_add_encode_oid() ! {
	mut seq := new_sequence()

	o1 := new_oid_from_string('1.2.3')! // size = 4
	o2 := new_oid_from_string('1.2.4')! // size = 4
	o3 := new_boolean(true) // size = 3

	seq.add(o1)
	seq.add(o2)
	seq.add(o3)

	assert seq.tag() == new_tag(.universal, true, int(TagType.sequence))
	assert seq.length() == 11
	assert seq.size() == 13

	out := seq.encode()!
	exp := [u8(0x30), 0x0b, u8(0x06), 0x02, 0x2a, 0x03, u8(0x06), 0x02, 0x2a, 0x04, u8(0x01), 0x01,
		0xff]

	assert out == exp

	back := decode_sequence(out)!
	//(back)
	assert back.encode()! == exp
	assert back.elements.len == 3
	assert back.tag.constructed == true
	assert back.elements[0].encode()! == [u8(0x06), 0x02, 0x2a, 0x03]
	assert back.elements[1].encode()! == [u8(0x06), 0x02, 0x2a, 0x04]
	assert back.elements[2].encode()! == [u8(0x01), 0x01, 0xff]
}

fn test_sequence_add_encode_integer() ! {
	mut seq := new_sequence()

	o1 := new_integer(127)
	o2 := new_boolean(true)
	o3 := new_integer(math.max_i64)
	seq.add(o1)
	seq.add(o2)
	seq.add(o3)

	assert seq.tag() == new_tag(.universal, true, int(TagType.sequence))
	assert seq.length() == 16
	assert seq.size() == 18

	out := seq.encode()!
	// math.max_i64 serialize to 02087fffffffffffffff
	exp := [u8(0x30), 0x10, u8(0x02), 0x01, 0x7f, u8(0x01), 0x01, 0xff, u8(0x02), 0x08, 0x7f, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff]

	assert out == exp

	back := decode_sequence(out)!

	assert back.elements.len == 3
	assert back.tag.number == 16
	assert back.tag.constructed == true
}

fn test_sequence_integer_bigint() ! {
	inp := big.integer_from_string('84885164052257330097714121751630835360966663883732297726369399')!
	mut seq := new_sequence()

	o1 := new_integer(inp)
	o2 := new_boolean(true)
	o3 := new_null()
	seq.add(o1)
	seq.add(o2)
	seq.add(o3)

	out := seq.encode()!

	assert seq.length() == 28 + 3 + 2
	assert seq.size() == 2 + 28 + 3 + 2
	exp := [u8(0x30), 33, u8(0x02), 26, 52, 210, 252, 160, 105, 66, 145, 88, 8, 53, 227, 150, 221,
		98, 149, 87, 146, 121, 109, 20, 162, 246, 230, 65, 30, 119, u8(0x01), 0x01, 0xff, u8(0x05),
		0x00]

	assert out == exp

	back := decode_sequence(exp)! // Sequence
	assert back.encode()! == out

	assert back.elements.len == 3
	assert back.tag.number == 16
	assert back.tag.constructed == true

	assert back.elements[1].encode()! == [u8(0x01), 0x01, 0xff]
}

fn test_sequence_of_string() ! {
	str := 'iloveyou' // 8
	mut seq := new_sequence()
	o1 := new_null()
	o2 := new_utf8string(str)!
	o3 := new_ia5string(str)!
	seq.add(o1)
	seq.add(o2)
	seq.add(o3)

	assert seq.length() == 22
	assert seq.size() == 24
	out := seq.encode()!
	exp := [u8(0x30), 22, u8(0x05), 0x00, u8(12), 8, u8(105), 108, 111, 118, 101, 121, 111, 117,
		u8(22), 8, u8(105), 108, 111, 118, 101, 121, 111, 117]
	assert out == exp

	back := decode_sequence(out)!

	assert back.encode()! == exp
}

fn test_sequnce_of_sequence() {
	mut seq := new_sequence()

	seq.add(new_null())
	seq.add(new_boolean(false))

	assert seq.encode()! == [u8(0x30), 5, 5, 0, 1, 1, 0]

	mut seq2 := new_sequence()
	seq2.add(new_integer(int(5)))
	seq2.add(new_integer(i64(86424278346)))

	assert seq2.encode()! == [u8(0x30), 10, 2, 1, 5, 2, 5, 0x14, 0x1f, 0x49, 0xd5, 0x4a]
	seq.add(seq2)

	assert seq.encode()! == [u8(0x30), 17, 5, 0, 1, 1, 0, u8(0x30), 10, 2, 1, 5, 2, 5, 0x14, 0x1f,
		0x49, 0xd5, 0x4a]

	out := seq.encode()!
	back := der_decode(out)!

	if back is Sequence {
		assert back == seq
		assert back.elements.len == 3
		assert back.elements[0] is Null
		assert back.elements[1] is Boolean
		assert back.elements[2] is Sequence

		two := back.elements[2]
		if two is Sequence {
			assert two.elements[0] is AsnInteger
			assert two.elements[1] is AsnInteger
			assert two.elements[1].length() == 5
		}
	}
}
*/
