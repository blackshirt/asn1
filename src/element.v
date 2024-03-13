module asn1

// Params is optional params passed to pack or unpacking
// of tag, length or ASN.1 element to drive how encoding works.
@[params]
pub struct Params {}

interface ElementBase {
	type_class() Class
	is_compound() bool
	// Otherwise is primitive
	tag() Tag
	is_type(t Tag) bool
	expect_type(t Tag) ElementBase
	//  Check whether the element is tagged (context specific).
	is_tagged() bool
}

enum TaggedMode {
	implicit
	explicit
}

// Tagged type element
struct TaggedType {
	// class of TaggedType element was default to .context_specific
	expected_tag Tag
	mode         TaggedMode = .explicit
	inner_el     Element
}

fn (tt TaggedType) pack_to_asn1(mut to []u8, mode EncodingMode, p Params) ! {
	match mode {
		.der {
			match tt.mode {
				.explicit {
					// wraps the inner element with this tag and length
					tt.expected_tag.pack_to_asn1(mut to, .der)!
					length := tt.inner_el.element_length()
					len := Length.from_i64(length)!
					len.pack_to_asn1(mut to, mode)!
					tt.inner_el.pack_to_asn1(mut to, mode)!
				}
				.implicit {
					// replace the tag.of inner element with this tag
					tt.expected_tag.pack_to_asn1(mut to, .der)!
					tt.inner_el.length.pack_to_asn1(mut to, mode)!
					to << tt.inner_el.content
				}
			}
		}
		else {
			return error('unsupported mode')
		}
	}
}

struct Element {
	tag    Tag
	length Length
	raw    []u8

	is_tagged bool
	inner_el  ?Element
}

fn (e Element) packed_length() int {
	mut n := 0
	n += e.tag.packed_length()
	n += e.length.packed_length()
	n += e.content.len

	return n
}

fn (e Element) pack_to_asn1(mut to []u8, mode EncodingMode, p Params) ! {
	match mode {
		.der {
			e.tag.pack_to_asn1(mut to, .der)!
			e.length.pack_to_asn1(mut to, .der)!
			to << e.content
		}
		else {
			return error('unsupported mode')
		}
	}
}

// encoding mode
pub enum EncodingMode {
	der = 0
	ber = 1
	cer = 2
	oer = 3
	per = 4
	xer = 5
}
