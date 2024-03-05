module core

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
	tag      Tag
	mode     TaggedMode = .explicit
	inner_el Element
}

fn (tt TaggedType) pack_to_asn1(mut to []u8, mode EncodingMode) ! {
	match mode {
		.der {
			match tt.mode {
				.explicit {
					// wraps the inner element with this tag and length
					tt.tag.pack_to_asn1(mut to)
					length := tt.inner_el.element_length()
					len := Length.from_int(length)
					len.pack_to_asn1(mut to, mode)!
					tt.inner_el.pack_to_asn1(mut to, mode)!
				}
				.implicit {
					// replace the tag.of inner element with this tag
					tt.tag.pack_to_asn1(mut to)
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
	// raw payload of this element
	content []u8
}

fn (e Element) element_length() int {
	mut n := 0
	n += e.tag.tag_length()
	n += e.length.length()
	n += e.content.len

	return n
}

fn (e Element) pack_to_asn1(mut to []u8, mode EncodingMode) ! {
	match mode {
		.der {
			e.tag.pack_to_asn1(mut to)
			e.length.pack_to_asn1(mut to, .der)!
			to << e.content
		}
		else {
			return error('unsupported mode')
		}
	}
}

fn (e Element) is_compound() bool {
	return e.tag.compound
}

// encoding mode
enum EncodingMode {
	der = 0
	ber = 1
	cer = 2
	oer = 3
	per = 4
	xer = 5
}
