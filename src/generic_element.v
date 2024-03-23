module asn1

// ASN.1 Element implemented as generic type
// Its possible after a patch from @FelipePena being merged to the c.
// see https://github.com/vlang/v/commit/29e5124c48b613eaac9e1115f428f8164b66f51d
// Its a good to give a try,
//
struct ASN1Element[T] {
	element T
}

// new creates a new generic ASN.1 Element from T type
pub fn Elm.new[T](el T) ASN1Element[T] {
	return ASN1Element[T]{
		element: el
	}
}

// tag gets the tag of this ASN1 Element
pub fn (e ASN1Element[T]) tag() Tag {
	return e.element.tag()
}

// element gets the underlying T type element from this generic ASN1 Element
pub fn (e ASN1Element[T]) element() T {
	return e.element
}

// encode serializes this element into bytes array in out
pub fn (e ASN1Element[T]) encode(mut out []u8, p Params) ! {
	e.element.encode(mut out, p)
}

// decode unserializes this bytes arrays in src into ASN1.1 element structure.
pub fn ASN1Element.decode[T](src []u8, loc i64, p Params) !(T, i64) {
	t, idx := T.decode(src, loc, p)!
	return t, idx
}
