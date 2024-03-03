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
	
struct TaggedType {
	// class of TaggedType element default to .context_specifiv
	cls        Class = .context_specifiv
	compound   bool
	tag_number TagValue
	mode       TaggedMode = .explicit
	inner_el   Element
}
	
struct Element {
	cls        Class
	compound   bool
	tag_number TagValue
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
