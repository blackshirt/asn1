// Copyright (c) 2022, 2023 blackshirt. All rights reserved.
// Use of this source code is governed by a MIT License
// that can be found in the LICENSE file.
module asn1

// SEQUENCE and SEQUENCE OF handling
//
// https://letsencrypt.org/docs/a-warm-welcome-to-asn1-and-der
// These are two very different types.
// A SEQUENCE is equivalent to “struct” in most programming languages.
// It holds a fixed number of fields of different types.
// A SEQUENCE OF, holds an arbitrary number of fields of a single type.
// This is analogous to an array or a list in a programming language.
// Sequence structure can represents both SEQUENCE and SEQUENCE OF type.
// The encoding of a sequence value shall be constructed.
pub struct Sequence {
	// should represents sequence tag
	tag Tag = new_tag(Class.universal, true, int(TagType.sequence))
mut:
	elements []Encoder // elements of the sequence
}

fn new_encoder_seq(seq Sequence) Encoder {
	return seq
}

// new_sequence creates empty universal class of sequence type.
// for other ASN.1 class, see `new_sequence_with_class`
pub fn new_sequence() Sequence {
	seq := new_sequence_with_class(.universal)
	return seq
}

// new_sequence_with_class creates new empty sequence with specific ASN.1 class.
pub fn new_sequence_with_class(c Class) Sequence {
	seq := Sequence{
		tag: new_tag(c, true, int(TagType.sequence))
	}
	return seq
}

fn new_sequence_from_multiencoder(me []Encoder) !Sequence {
	mut seq := new_sequence()
	seq.add_multi(me)
	return seq
}

// new_sequence_from_bytes creates new SEQUENCE from bytes
fn new_sequence_from_bytes(src []u8) !Sequence {
	seq := decode_sequence(src)!
	return seq
}

// new_sequenceof_from_bytes creates new SEQUENCEOF from bytes
fn new_sequenceof_from_bytes(src []u8) !Sequence {
	seq := decode_sequence(src)!

	if !is_sequence_of(seq) {
		return error('sequence contains some different elements, its not sequenceof')
	}
	return seq
}

fn (seq Sequence) tag() Tag {
	return seq.tag
}

pub fn (seq Sequence) length() int {
	mut length := 0
	for obj in seq.elements {
		n := obj.size()
		length += n
	}
	return length
}

pub fn (seq Sequence) size() int {
	mut size := 0

	// calculates tag length
	t := calc_tag_length(seq.tag())
	size += t

	// calculates length of length
	lol := calc_length_of_length(seq.length())
	size += lol

	// length of sequence elements.
	size += seq.length()

	return size
}

pub fn (seq Sequence) encode() ![]u8 {
	mut dst := []u8{}

	serialize_tag(mut dst, seq.tag())
	serialize_length(mut dst, seq.length())

	el := seq.elements.encode()!
	dst << el
	return dst
}

pub fn (mut seq Sequence) add(obj Encoder) Sequence {
	seq.elements.add(obj)
	return seq
}

pub fn (mut seq Sequence) add_multi(elements []Encoder) Sequence {
	seq.elements.add_multi(elements)
	return seq
}

// is_sequence_of checks whether the sequence `seq` holds the same elements (its a SEQUENCE OF type).
fn is_sequence_of(seq Sequence) bool {
	tag := seq.tag.number
	if tag != int(TagType.sequence) {
		return false
	}
	// take the first obj's tag
	tag0 := seq.elements[0].tag()
	for obj in seq.elements {
		if obj.tag() != tag0 {
			return false
		}
	}
	// return seq.elements.all(it.tag() == tag0)
	return true
}

fn decode_sequence(src []u8) !Sequence {
	if src.len < 2 {
		return error('invalid minimal length')
	}
	tag, pos := read_tag(src, 0)!
	if !tag.is_sequence_tag() {
		return error('bad tags n look like not a sequence tag=${tag}')
	}

	length, next := decode_length(src, pos)!
	sub := read_bytes(src, next, length)!

	seq := parse_seq(tag, sub)!

	return seq
}

// main routine for parsing sequence
fn parse_seq(tag Tag, contents []u8) !Sequence {
	if !tag.is_sequence_tag() {
		return error('not seq tag')
	}

	mut i := 0
	mut seq := new_sequence_with_class(tag.class)
	for i < contents.len {
		t, idx := read_tag(contents, i)!
		ln, next := decode_length(contents, idx)!

		sub := read_bytes(contents, next, ln)!
		match t.constructed {
			true {
				obj := parse_compound_element(t, sub)!
				seq.add(obj)
				i += obj.size()
			}
			false {
				obj := parse_primitive_element(t, sub)!
				seq.add(obj)
				i += obj.size()
			}
		}
	}
	return seq
}
