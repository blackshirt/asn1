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

struct Element {
	tag Tag
}

fn (e Element) is_constructed() bool {
	return e.tag.compound
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
