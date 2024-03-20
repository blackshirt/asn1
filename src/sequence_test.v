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
	seq1.add_element(Boolean.new(true))!
	seq1.add_element(Null.new())!
	seq1.add_element(Boolean.new(false))!

	// lets create another sequences, where it contains primitive element and first sequence created above.
	mut seq2 := Sequence.new(false)!
	seq2.add_element(Boolean.new(false))!
	seq2.add_element(seq1)!
	seq2.add_element(Boolean.new(true))!

	// lets serialize it to bytes
	mut out := []u8{}
	seq2.pack_to_asn1(mut out)!
	expected := [u8(0x30), 16, u8(0x01), 0x01, 0x00, u8(0x30), 8, 0x01, 0x01, 0xff, u8(0x05), 0x00,
		u8(0x01), 0x01, 0x00, u8(0x01), 0x01, 0xff]
	// assert for right value
	assert seq2.payload_length() == 16
	assert seq2.packed_length() == 18
	assert out == expected
}

fn test_sequence_der_decode() ! {
	data := [u8(0x30), 16, u8(0x01), 0x01, 0x00, u8(0x30), 8, u8(0x01), 0x01, 0xff, u8(0x05), 0x00,
		u8(0x01), 0x01, 0x00, u8(0x01), 0x01, 0xff]
	seq, n := Sequence.unpack_from_asn1(data, 0)!
	assert seq.tag.is_constructed() == true
	assert seq.tag.tag_number() == int(TagType.sequence)
	assert n == 18
	assert seq.elements.len == 3
	els := seq.elements()!

	assert els[0].tag() == new_tag(.universal, false, int(TagType.boolean))!
	assert els[0].payload()! == [u8(0x00)]

	el1 := els[1] as Sequence
	assert el1.elements.len == 3 // [boolean(true), null, boolean(false)]
	el10 := el1.elements[0] as Boolean
	assert el10.value == true
	el11 := el1.elements[1] as Null
	assert el11 == Null{}
	el12 := el1.elements[2] as Boolean
	assert el12.value == false

	el2 := els[2] as Boolean
	assert el2.value == true
}

fn test_sequence_add_and_encode_boolean() {
	o1 := Boolean.new(false)
	o2 := Boolean.new(true)
	o3 := Boolean.new(true)
	mut seq := Sequence.new(false)!
	seq.add_element(o1)!
	seq.add_element(o2)!
	seq.add_element(o3)!

	length := seq.payload_length()
	assert length == 9

	size := seq.packed_length()
	assert size == 11

	mut out := []u8{}
	seq.pack_to_asn1(mut out)!

	exp := [u8(0x30), 0x09, 0x01, 0x01, 0x00, 0x01, 0x01, 0xff, 0x01, 0x01, 0xff]

	assert out == exp
	assert exp.len == size

	back, n := Sequence.unpack_from_asn1(out, 0)!
	assert n == exp.len

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
	mut seq := Sequence.new(false)!

	o1 := Oid.from_string('1.2.3')! // size = 4
	o2 := Oid.from_string('1.2.4')! // size = 4
	o3 := Boolean.new(true) // size = 3

	seq.add_element(o1)!
	seq.add_element(o2)!
	seq.add_element(o3)!

	assert seq.tag() == new_tag(.universal, true, int(TagType.sequence))!
	assert seq.payload_length() == 11
	assert seq.packed_length() == 13

	mut out := []u8{}
	seq.pack_to_asn1(mut out)!
	exp := [u8(0x30), 0x0b, u8(0x06), 0x02, 0x2a, 0x03, u8(0x06), 0x02, 0x2a, 0x04, u8(0x01), 0x01,
		0xff]

	assert out == exp

	back, n := Sequence.unpack_from_asn1(out, 0)!
	assert n == exp.len
	//(back)

	assert back.elements.len == 3
	assert back.tag.constructed == true
	//
	out.clear()
	back.elements[0].pack_to_asn1(mut out)!
	assert out == [u8(0x06), 0x02, 0x2a, 0x03]
	//
	out.clear()
	back.elements[1].pack_to_asn1(mut out)!
	assert out == [u8(0x06), 0x02, 0x2a, 0x04]
	//
	out.clear()
	back.elements[2].pack_to_asn1(mut out)!
	assert out == [u8(0x01), 0x01, 0xff]
}

fn test_sequence_add_encode_integer() ! {
	mut seq := Sequence.new(false)!

	o1 := Integer.from_i64(127)
	o2 := Boolean.new(true)
	o3 := Integer.from_i64(max_i64)
	seq.add_element(o1)!
	seq.add_element(o2)!
	seq.add_element(o3)!

	assert seq.tag() == new_tag(.universal, true, int(TagType.sequence))!
	assert seq.payload_length() == 16
	assert seq.packed_length() == 18

	mut out := []u8{}
	seq.pack_to_asn1(mut out)!
	// math.max_i64 serialize to 02087fffffffffffffff
	exp := [u8(0x30), 0x10, u8(0x02), 0x01, 0x7f, u8(0x01), 0x01, 0xff, u8(0x02), 0x08, 0x7f, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff]

	assert out == exp

	back, n := Sequence.unpack_from_asn1(out, 0)!
	assert n == exp.len

	assert back.elements.len == 3
	assert back.tag.number == 16
	assert back.tag.constructed == true
}

fn test_sequence_integer_bigint() ! {
	inp := big.integer_from_string('84885164052257330097714121751630835360966663883732297726369399')!
	mut seq := Sequence.new(false)!

	o1 := Integer.from_bigint(inp)!
	o2 := Boolean.new(true)
	o3 := Null.new()
	seq.add_element(o1)!
	seq.add_element(o2)!
	seq.add_element(o3)!

	mut out := []u8{}
	seq.pack_to_asn1(mut out)!

	assert seq.payload_length() == 28 + 3 + 2
	assert seq.packed_length() == 2 + 28 + 3 + 2
	exp := [u8(0x30), 33, u8(0x02), 26, 52, 210, 252, 160, 105, 66, 145, 88, 8, 53, 227, 150, 221,
		98, 149, 87, 146, 121, 109, 20, 162, 246, 230, 65, 30, 119, u8(0x01), 0x01, 0xff, u8(0x05),
		0x00]

	assert out == exp

	back, n := Sequence.unpack_from_asn1(out, 0)! // Sequence
	assert n == exp.len

	// clear out
	out.clear()
	back.pack_to_asn1(mut out)!
	assert out == exp

	assert back.elements.len == 3
	assert back.tag.number == 16
	assert back.tag.constructed == true

	// clear out
	out.clear()
	back.elements[1].pack_to_asn1(mut out)!
	assert out == [u8(0x01), 0x01, 0xff]
}

fn test_sequence_of_string() ! {
	str := 'iloveyou' // 8
	mut seq := Sequence.new(false)!
	o1 := Null.new()
	o2 := UTF8String.from_string(str)!
	o3 := IA5String.from_string(str)!
	seq.add_element(o1)!
	seq.add_element(o2)!
	seq.add_element(o3)!

	assert seq.payload_length() == 22
	assert seq.packed_length() == 24

	mut out := []u8{}
	seq.pack_to_asn1(mut out)!
	exp := [u8(0x30), 22, u8(0x05), 0x00, u8(12), 8, u8(105), 108, 111, 118, 101, 121, 111, 117,
		u8(22), 8, u8(105), 108, 111, 118, 101, 121, 111, 117]
	assert out == exp

	back, n := Sequence.unpack_from_asn1(out, 0)!
	assert n == exp.len
	// clears out
	out.clear()
	back.pack_to_asn1(mut out)!
	assert out == exp
}

fn test_sequnce_of_sequence() {
	mut seq := Sequence.new(false)!

	seq.add_element(Null.new())!
	seq.add_element(Boolean.new(false))!

	mut out := []u8{}
	seq.pack_to_asn1(mut out)!
	assert out == [u8(0x30), 5, 5, 0, 1, 1, 0]

	mut seq2 := Sequence.new(false)!
	seq2.add_element(Integer.from_i64(int(5)))!
	seq2.add_element(Integer.from_i64(i64(86424278346)))!

	// clear out
	out.clear()
	seq2.pack_to_asn1(mut out)!
	assert out == [u8(0x30), 10, 2, 1, 5, 2, 5, 0x14, 0x1f, 0x49, 0xd5, 0x4a]

	seq.add_element(seq2)!
	// clear out
	out.clear()
	seq.pack_to_asn1(mut out)!
	assert out == [u8(0x30), 17, 5, 0, 1, 1, 0, u8(0x30), 10, 2, 1, 5, 2, 5, 0x14, 0x1f, 0x49,
		0xd5, 0x4a]

	back, n := Sequence.unpack_from_asn1(out, 0)!
	assert n == out.len

	assert back == seq
	assert back.elements.len == 3
	assert back.elements[0] is Null
	assert back.elements[1] is Boolean
	assert back.elements[2] is Sequence

	two := back.elements[2]
	if two is Sequence {
		assert two.elements[0] is Integer
		assert two.elements[1] is Integer
		assert two.elements[1].payload_length() == 5
	}
}
