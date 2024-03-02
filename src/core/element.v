module core

interface ElementBase {
    type_class() Class
    is_constructed() bool // Otherwise is primitive
    tag() Tag 
    is_type(t Tag) bool 
    expect_type(t Tag) ElementBase
    //  Check whether the element is tagged (context specific).
    is_tagged() bool 
}

struct Element {
    type_tag Tag 
    indefinite_length bool = false
}

// encoding mode 
enum Mode {
    der = 0
    ber = 1
    cer = 2
    per = 3
    xer = 4
}