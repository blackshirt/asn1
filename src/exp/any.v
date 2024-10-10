// Copyright (c) 2022, 2023 blackshirt. All rights reserved.
// Use of this source code is governed by a MIT License
// that can be found in the LICENSE file.
module asn1

// ANY DEFINED BY
@[noinit]
struct Any {
	name   string
	marker Element
}

fn (a Any) tag() Tag {
	return a.marker.tag()
}

fn (a Any) payload() ![]u8 {
	return a.marker.payload()!
}
