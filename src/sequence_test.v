// Copyright (c) 2022, 2023 blackshirt. All rights reserved.
// Use of this source code is governed by a MIT License
// that can be found in the LICENSE file.
module asn1

import math.big

fn test_sequence_with_multi_items() ! {
	mut seq := Sequence{}

	o1 := Boolean.new(true) // 3
	o2 := UtcTime.new('191215190210Z')! // 15
	o3 := GeneralizedTime.new('20100102030405Z')! // 17

	seq.add_element(o1)!
	seq.add_element(o2)!
	seq.add_element(o3)!

	assert seq.payload()!.len == 3 + 15 + 17 // 35
	assert encoded_len(seq) == 2 + 35

	out := encode(seq)!
	exp := [u8(0x30), 35, u8(0x01), 0x01, 0xff, u8(0x17), 0x0D, 49, 57, 49, 50, 49, 53, 49, 57,
		48, 50, 49, 48, 90, u8(0x18), 0x0f, 50, 48, 49, 48, 48, 49, 48, 50, 48, 51, 48, 52, 48,
		53, 90]

	assert out == exp
}

fn test_sequence_contains_other_seq() ! {
	// lets create first sequence
	mut seq1 := Sequence{}
	// add two primitive elements to the sequence
	seq1.add_element(Boolean.new(true))!
	seq1.add_element(Null.new())!
	seq1.force_add_element(Boolean.new(false), true)!

	// lets create another sequences, where it contains primitive element and first sequence created above.
	mut seq2 := Sequence{}
	seq2.add_element(Boolean.new(false))!
	seq2.add_element(seq1)!
	// you should force add element to allow add second Boolean, by default its not allowed
	seq2.force_add_element(Boolean.new(true), true)!

	// lets serialize it to bytes

	out := encode(seq2)!

	expected := [u8(0x30), 16, u8(0x01), 0x01, 0x00, u8(0x30), 8, 0x01, 0x01, 0xff, u8(0x05), 0x00,
		u8(0x01), 0x01, 0x00, u8(0x01), 0x01, 0xff]
	// assert for right value
	assert seq2.payload()!.len == 16
	assert encoded_len(seq2) == 18
	assert out == expected

	seq2_back, _ := Sequence.decode(expected)!
	assert seq2_back.fields()[1] is Sequence
}

fn test_sequence_der_decode() ! {
	data := [u8(0x30), 16, u8(0x01), 0x01, 0x00, u8(0x30), 8, u8(0x01), 0x01, 0xff, u8(0x05), 0x00,
		u8(0x01), 0x01, 0x00, u8(0x01), 0x01, 0xff]

	seq, n := Sequence.decode(data)!
	assert seq.tag().is_constructed() == true
	assert seq.tag().tag_number() == int(TagType.sequence)
	assert n == 18
	assert seq.fields().len == 3
	els := seq.fields()

	assert els[0].tag() == Tag.new(.universal, false, int(TagType.boolean))!
	assert els[0].payload()! == [u8(0x00)]

	el1 := els[1] as Sequence
	assert el1.fields().len == 3 // [true, null, false]
	el10 := el1.fields()[0] as Boolean
	assert el10.value() == true
	el11 := el1.fields()[1] as Null
	assert el11 == Null{}
	el12 := el1.fields()[2] as Boolean
	assert el12.value() == false

	el2 := els[2] as Boolean
	assert el2.value() == true
}

fn test_sequence_add_and_encode_boolean() {
	o1 := Boolean.new(false)
	o2 := Boolean.new(true)
	o3 := Null.new()
	mut seq := Sequence{}
	seq.add_element(o1)!
	seq.add_element(o2)!
	seq.add_element(o3)!

	length := seq.payload()!.len
	assert length == 8

	size := encoded_len(seq)
	assert size == 10

	out := encode(seq)!

	exp := [u8(0x30), 0x08, 0x01, 0x01, 0x00, 0x01, 0x01, 0xff, 0x05, 0x00]

	assert out == exp
	assert exp.len == size

	back, n := Sequence.decode(out)!
	assert n == exp.len

	assert back.fields().len == 3

	assert back.tag().number == 0x10
	assert back.tag().constructed == true
	assert back.tag().class == .universal

	assert back.fields()[0].tag().class == .universal
	assert back.fields()[0].tag().constructed == false
	assert back.fields()[0].tag().number == 0x01

	assert back.fields()[1].tag().class == .universal
	assert back.fields()[1].tag().constructed == false
	assert back.fields()[1].tag().number == 0x01

	assert back.fields()[2].tag().number == 0x05
	assert back.fields()[2].tag().constructed == false
}

fn test_sequence_add_encode_oid() ! {
	mut seq := Sequence{}

	o1 := Oid.new('1.2.3')! // size = 4
	o2 := Oid.new('1.2.4')! // size = 4
	o3 := Boolean.new(true) // size = 3

	seq.add_element(o1)!
	seq.add_element(o2)!
	seq.add_element(o3)!

	assert seq.tag() == Tag.new(.universal, true, int(TagType.sequence))!
	assert seq.payload()!.len == 11
	assert encoded_len(seq) == 13

	mut out := encode(seq)!
	exp := [u8(0x30), 0x0b, u8(0x06), 0x02, 0x2a, 0x03, u8(0x06), 0x02, 0x2a, 0x04, u8(0x01), 0x01,
		0xff]

	assert out == exp

	back, n := Sequence.decode(out)!
	assert n == exp.len
	//(back)

	assert back.fields().len == 3
	assert back.tag().constructed == true
	//
	out.clear()
	out = encode(back.fields()[0])!
	assert out == [u8(0x06), 0x02, 0x2a, 0x03]
	//
	out.clear()
	out = encode(back.fields()[1])!
	assert out == [u8(0x06), 0x02, 0x2a, 0x04]
	//
	out.clear()
	out = encode(back.fields()[2])!
	assert out == [u8(0x01), 0x01, 0xff]
}

/*
fn test_sequence_add_encode_integer() ! {
	mut seq := Sequence.new(false)!

	o1 := Integer.from_i64(127)
	o2 := Boolean.new(true)
	o3 := Integer.from_i64(max_i64)
	seq.add_element(o1)!
	seq.add_element(o2)!
	seq.add_element(o3)!

	assert seq.tag() == Tag.new(.universal, true, int(TagType.sequence))!
	assert seq.length()! == 16
	assert seq.packed_length()! == 18

	mut out := []u8{}
	seq.encode(mut out)!
	// math.max_i64 serialize to 02087fffffffffffffff
	exp := [u8(0x30), 0x10, u8(0x02), 0x01, 0x7f, u8(0x01), 0x01, 0xff, u8(0x02), 0x08, 0x7f, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff]

	assert out == exp

	back, n := Sequence.decode(out)!
	assert n == exp.len

	assert back.fields().len == 3
	assert back.tag().number == 16
	assert back.tag().constructed == true
}

fn test_sequence_integer_bigint() ! {
	inp := big.integer_from_string('84885164052257330097714121751630835360966663883732297726369399')!
	mut seq := Sequence.new(false)!

	o1 := Integer.from_bigint(inp)
	o2 := Boolean.new(true)
	o3 := Null.new()
	seq.add_element(o1)!
	seq.add_element(o2)!
	seq.add_element(o3)!

	mut out := []u8{}
	seq.encode(mut out)!

	assert seq.length()! == 28 + 3 + 2
	assert seq.packed_length()! == 2 + 28 + 3 + 2
	exp := [u8(0x30), 33, u8(0x02), 26, 52, 210, 252, 160, 105, 66, 145, 88, 8, 53, 227, 150, 221,
		98, 149, 87, 146, 121, 109, 20, 162, 246, 230, 65, 30, 119, u8(0x01), 0x01, 0xff, u8(0x05),
		0x00]

	assert out == exp

	back, n := Sequence.decode(out)! // Sequence
	assert n == exp.len

	// clear out
	out.clear()
	back.encode(mut out)!
	assert out == exp

	assert back.fields().len == 3
	assert back.tag().number == 16
	assert back.tag().constructed == true

	// clear out
	out.clear()
	back.fields()[1].encode(mut out)!
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

	assert seq.length()! == 22
	assert seq.packed_length()! == 24

	mut out := []u8{}
	seq.encode(mut out)!
	exp := [u8(0x30), 22, u8(0x05), 0x00, u8(12), 8, u8(105), 108, 111, 118, 101, 121, 111, 117,
		u8(22), 8, u8(105), 108, 111, 118, 101, 121, 111, 117]
	assert out == exp

	back, n := Sequence.decode(out)!
	assert n == exp.len
	// clears out
	out.clear()
	back.encode(mut out)!
	assert out == exp
}

fn test_sequnce_of_sequence() {
	mut seq := Sequence.new(false)!

	seq.add_element(Null.new())!
	seq.add_element(Boolean.new(false))!

	mut out := []u8{}
	seq.encode(mut out)!
	assert out == [u8(0x30), 5, 5, 0, 1, 1, 0]

	mut seq2 := Sequence.new(false)!
	seq2.add_element(Integer.from_i64(int(5)))!
	seq2.add_element(Integer.from_i64(i64(86424278346)))!

	// clear out
	out.clear()
	seq2.encode(mut out)!
	assert out == [u8(0x30), 10, 2, 1, 5, 2, 5, 0x14, 0x1f, 0x49, 0xd5, 0x4a]

	seq.add_element(seq2)!
	// clear out
	out.clear()
	seq.encode(mut out)!
	assert out == [u8(0x30), 17, 5, 0, 1, 1, 0, u8(0x30), 10, 2, 1, 5, 2, 5, 0x14, 0x1f, 0x49,
		0xd5, 0x4a]

	back, n := Sequence.decode(out)!
	assert n == out.len

	assert back == seq
	assert back.fields().len == 3
	assert back.fields()[0] is Null
	assert back.fields()[1] is Boolean
	assert back.fields()[2] is Sequence

	two := back.fields()[2]
	if two is Sequence {
		assert two.fields()[0] is Integer
		assert two.fields()[1] is Integer
		assert two.fields()[1].length()! == 5
	}
}
*/
