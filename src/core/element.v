module core

interface ElementBase {
	type_class() Class
	is_constructed() bool
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
	// class of TaggedType element was default to .context_specifiv
	tag      Tag
	mode     TaggedMode = .explicit
	inner_el Element
}
	
fn (tt TaggedType) pack_and_wrap(mut to []u8) ! {
	match tt mode {
		.explicit {
			// wraps the inner element with this tag and length
			tt.tag.pack(mut to)!
			length:= tt.inner_el.packed_length()!
			len := Length.from_int(length)!
			len.pack(mut to)!
			tt.inner_el.pack(mut to)!
		}
		.implicit {
			// replace the tag.of inner element with this tag
			tt.tag.pack(mut to)!
			tt.inner_el.length.pack(mut to)!
			to << tt.inner_el.content
		}
	}
}
	
struct Element {
	cls        Class
	compound   bool
	tag_number TagNumber
	length     Length
	// raw payload of this element
	content    []u8
}

fn (e Element) is_constructed() bool {
	return e.compound
}

// encoding mode
enum Mode {
	der = 0
	ber = 1
	cer = 2
	oer = 3
	per = 4
	xer = 5
}
