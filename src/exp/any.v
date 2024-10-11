// Copyright (c) 2022, 2023 blackshirt. All rights reserved.
// Use of this source code is governed by a MIT License
// that can be found in the LICENSE file.
module asn1

// ANY DEFINED BY
@[noinit]
struct Any {
mut:
	marker string = 'any'
	params Element
}

fn Any.new(marker string, params Element) Any {
	return Any{marker, params}
}

fn Any.decode(bytes []u8) !Any {
	return error('not implemented')
}

fn (a Any) tag() Tag {
	return a.params.tag()
}

fn (a Any) payload() ![]u8 {
	return a.params.payload()!
}
