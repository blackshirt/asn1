// Copyright (c) 2022, 2023 blackshirt. All rights reserved.
// Use of this source code is governed by a MIT License
// that can be found in the LICENSE file.
module asn1

fn test_explicit_context_null_pack_unpack() ! {
	el := Null.new()
	ex1 := TaggedType.explicit_context(el, 0)!

	mut out := []u8{}
	ex1.pack_to_asn1(mut out)!
	exp := [u8(0xa0), 0x02, 0x05, 0x00]

	assert out == exp
	// unpack back
	ttback, _ := TaggedType.unpack_from_asn1(out, 0, .explicit, el.tag())!
	assert ttback == ex1
	assert ttback.inner_el == el
}

fn test_explicit_context_nested_pack_unpack() ! {
	el := Null.new()

	ex1 := TaggedType.explicit_context(el, 1)!
	exp2 := TaggedType.explicit_context(ex1, 2)!
	// el1 := new_explicit_context(new_null(), 1)
	// ex1 := new_explicit_context(el1, 2)

	mut out := []u8{}
	ex2.pack_to_asn1(mut out)!
	exp := [u8(0xa2), 0x04, 0xa1, 0x02, 0x05, 0x00]

	assert out == exp

	// clears out
	out.clear()
	ex1.pack_to_asn1(mut out)!
	assert out == [u8(0x05), 0x00]
}

/*
fn test_asn1_example() ! {
	/*
	```asn.1
Example ::= SEQUENCE {
    greeting    UTF8String,
    answer      INTEGER,
    type    [1] EXPLICIT OBJECT IDENTIFIER
}
```*/
	mut seq := new_sequence()
	seq.add(new_utf8string('Hello')!) // tag : 12
	seq.add(new_integer(i64(42))) // tag 2
	seq.add(new_explicit_context(new_oid_from_string('1.3.6.1.3')!, 1))

	out := seq.encode()!

	exp := [u8(0x30), 18, u8(12), 5, 72, 101, 108, 108, 111, u8(2), 1, 42, u8(0xA1), 6, 6, 4, 43,
		6, 1, 3]
	assert out == exp

	back := der_decode(out)!
	if back is Sequence {
		assert back.elements[0] is UTF8String
		assert back.elements[1] is AsnInteger
		assert back.elements[2] is Tagged
	}
}
*/
