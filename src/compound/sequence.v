// Copyright (c) 2022, 2023 blackshirt. All rights reserved.
// Use of this source code is governed by a MIT License
// that can be found in the LICENSE file.
module compound

import asn1

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
struct Sequence {
mut:
	// The tag should represents sequence or sequenceof tag, ie, 0x30
	tag Tag = asn1.Tag{.universal, true, int(asn1.TagType.sequence)}
	// is_seqof should be set when this sequence is SequenceOf type 
	is_seqof  bool 
	// elements of the sequence
	elements []asn1.Element
}

// new creates a new empty Sequence. If is_seqof is true, a new Sequence 
// should be treated as a SequenceOf type, ie its an empty SequenceOf
fn Sequence.new(tag asn1.Tag, is_seqof bool, els []Element) !Sequence {
	if !tag.is_compound() && tag.tag_number() != int(asn1.TagType.sequence) {
		return error("Not a valid sequence tag")
	}
	return Sequence{
		is_seqof: is_seqof 
	}
}

// new creates new ASN.1 Sequence, when passed elements is holds the same tag,
// the Sequence.is_seqof flag is set to true 
fn Sequence.new(elements []asn1.Element) Sequence {
	mut seq := Sequence{
		elements: elements
	}
	// when this all elements is holds the same tag type, its a SequenceOf
	if seq.is_sequenceof_type() {
		seq.is_seqof = true 
	}
	return seq 
}

fn (mut seq Sequence) set_to_sequenceof() ! {
	if seq.elements.hold_thesame_tag() {
		seq.is_seqof = true 
		return 
	}
	// non-sequenceof, just return error 
	return error("Not holds sequenceof elements, you can't set the flag")
}

// is_sequenceof_type checks whether this sequence is SequenceOf type 
fn (seq Sequence) is_sequenceof_type() bool {
	// we assume the tag is sequence type
	// take the first obj's tag, and check if the all the element tags has the same type 
	tag0 := seq.elements[0].tag()
	return seq.elements.all(it.tag() == tag0) && seq.is_seqof
}

// add_element add the element el to this sequence. Its check whether its should be added when this 
// sequence is SequenceOf type 
fn (mut seq Sequence) add_element(el Element) ! {
	if seq.elements.len == 0 {
		// sequence elements is still empty, just add the element  
		seq.elements << el
		return 
	}
	// otherwise, sequence elements is not empty, so, lets performs check.
	// get the first element tag, when this sequence is SequenceOf type, to be added element 
	// has to be have the same tag with element already availables in sequence.
	tag0 := seq.elements[0].tag()
	if seq.is_seqof {
		if el.tag() != tag0 {
			return error("Sequence: adding different element to the SequenceOf element")
		}
		// has the same tag 
		seq.elements << el 
		return 
	}
	// otherwise, we can just append el into sequence elements
	seq.elements << el 
}

fn (s Sequence) tag() asn1.Tag {
	return s.tag
}

// valid_sequence_tag checks whether this sequence has a valid sequence tag and in constructed form 
fn (s Sequence) valid_sequence_tag() bool {
	return s.tag.is_compound() && s.tag.tag_number() == int(asn1.TagType.sequence)
}

// is_sequenceof_type checks whether the sequence `seq` holds the same elements (its a SEQUENCE OF type).
fn is_sequenceof_type(seq Sequence) bool {
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

	if !is_sequenceof_type(seq) {
		return error('sequence contains some different elements, its not sequenceof')
	}
	return seq
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

fn (mut seq Sequence) add(obj Encoder) Sequence {
	seq.elements.add(obj)
	return seq
}

fn (mut seq Sequence) add_multi(elements []Encoder) Sequence {
	seq.elements.add_multi(elements)
	return seq
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
