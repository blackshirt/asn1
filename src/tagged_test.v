// Copyright (c) 2022, 2023 blackshirt. All rights reserved.
// Use of this source code is governed by a MIT License
// that can be found in the LICENSE file.
module asn1

fn test_explicit_context_null_pack_unpack() ! {
	el := Null.new()
	ex1 := ContextElement.explicit_context(0, el)!

	out := encode(ex1)!
	exp := [u8(0xa0), 0x02, 0x05, 0x00]
	assert out == exp
	// unpack back
	ttback, _ := ContextElement.decode_with_mode(out, .explicit)!
	// ctxback := parse_context_specific_with_mode(tag Tag, content []u8, mode TaggedMode) !ContextElement {
	// ttback, _ := TaggedType.decode(out, 0, .explicit, el.tag())!
	assert ttback == ex1
	itt := ttback.inner_tag?
	assert itt.tag_number() == int(TagType.null)
}

fn test_explicit_context_nested_pack_unpack() ! {
	el := Null.new()

	ex1 := ContextElement.explicit_context(1, el)!
	ex2 := ContextElement.explicit_context(2, ex1)!

	mut out := encode(ex2)!
	exp := [u8(0xa2), 0x04, 0xa1, 0x02, 0x05, 0x00]

	assert out == exp

	// clears out
	out.clear()
	out = encode(ex1)!
	assert out == [u8(0xa1), 0x02, u8(0x05), 0x00]
}

fn test_asn1_example() ! {
	/*
	```asn.1
Example ::= SEQUENCE {
    greeting    UTF8String,
    answer      INTEGER,
    type    [1] EXPLICIT OBJECT IDENTIFIER
}
```*/
	oid := ObjectIdentifier.new('1.3.6.1.3')!
	expl := ContextElement.explicit_context(1, oid)!
	mut seq := Sequence{}
	seq.add_element(Utf8String.new('Hello')!)! // tag : 12
	seq.add_element(Integer.from_i64(i64(42)))! // tag 2
	seq.add_element(expl)!

	mut out := encode(seq)!

	exp := [u8(0x30), 18, u8(12), 5, 72, 101, 108, 108, 111, u8(2), 1, 42, u8(0xA1), 6, 6, 4, 43,
		6, 1, 3]
	assert out == exp

	back, n := Sequence.decode(out)!
	assert n == exp.len

	els := back.fields()
	assert els[0] is Utf8String
	assert els[1] is Integer
	mut els2 := els[2] as ContextElement

	els2.set_ctx_mode(.explicit)!
	els2.set_inner_tag(default_oid_tag)!
	// els2_tagged := els2.as_tagged(.explicit, oid.tag())!
	// assert els2_tagged == expl

	out.clear()
	out = encode(els2)!
	expected_ctx_type := [u8(0xA1), 6, 6, 4, 43, 6, 1, 3]
	assert out == expected_ctx_type
}
