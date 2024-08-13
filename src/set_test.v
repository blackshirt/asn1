// Copyright (c) 2022, 2023 blackshirt. All rights reserved.
// Use of this source code is governed by a MIT License
// that can be found in the LICENSE file.
module asn1

fn test_sort_the_set() {
	mut objs := []Element{}

	val12 := Integer.from_i64(12)
	val32 := Integer.from_i64(32)
	valbol := Boolean.new(false)
	valnull := Null.new()
	valapp := RawElement.new(Tag{.application, false, 34}, [u8(44), 45])
	valctx := RawElement.new(Tag{.context_specific, false, 35}, [u8(50), 55])

	objs << val12 // tag: 2
	objs << val32 // tag: 2
	objs << valctx //
	objs << valapp //
	objs << valbol // tag: 1
	objs << valnull // tag: 5

	awal := objs.clone()
	mut exp := []Element{}
	exp << valbol
	exp << val12
	exp << val32
	exp << valnull
	exp << valapp
	exp << valctx
	// [valbol, val12, val32, valnull, valapp, valctx]}
	objs.sort_the_set()
	// dump(objs)
<<<<<<< HEAD

=======
	mut exp := []Encoder{}
	exp << valbol
	exp << val12
	exp << val32
	exp << valnull
	exp << valapp
	exp << valctx 
	//[valbol, val12, val32, valnull, valapp, valctx]
>>>>>>> main
	assert awal != objs
	assert objs == exp
}

/*
fn test_sort_the_setof() ! {
	mut objs := []Element{}

	val1 := Integer.from_i64(1)
	val2 := Integer.from_i64(12)
	val3 := Integer.from_i64(323)
	val4 := Integer.from_i64(4325)
	val5 := Integer.from_i64(44446)
	val0 := Integer.from_i64(0)
	val6 := Boolean.new(false)

	// randomly added to array
	objs << val4 // tag: 2
	objs << val2 // tag: 2
	objs << val5 // tag: 2
	objs << val1 // tag: 2
	objs << val3 // tag: 2
	objs << val0 // tag: 2

	awal := objs.clone()
	awalexp := [val4, val2, val5, val1, val3, val0]
	assert awal == awalexp
	// dump(objs)

	objs.sort_the_setof()!

	// dump(objs)
	exp := [val0, val1, val2, val3, val4, val5]
	assert awal != objs
	assert objs == exp
}

fn test_set_encode() ! {
	mut set1 := Set.new(false)

	set1.add_multi([Boolean.new(false), Null.new(), Integer.from_i64(4)])
	// boolean tag:1 length: 3, integer tag:2 length: 3, null tag: 5 length: 2, total length: 8
	// so, it should sort to
	// [boolean, integer, null]
	exp := [u8(0x31), 8, 1, 1, 0, 2, 1, 4, 5, 0]
	out := set1.encode()!

	assert out == exp

	back := der_decode(exp)!

	assert out == back.encode()!
}

fn test_setof_encode() ! {
	mut set1 := Set{
		tag: new_tag(.universal, true, int(TagType.set))
	}

	set1.add_multi([Integer.from_i64(55), Integer.from_i64(4),
		Integer.from_i64(666)])
	// 666 serialized to [2, 154]
	// encoded sort: [int1, int2, int3]
	exp := [u8(0x31), 10, 2, 1, 4, 2, 1, 55, 2, 2, 2, 0x9a]
	out := set1.encode()!

	assert out == exp

	back := der_decode(exp)!
	if back is Set {
		// set is only sorted on encode() step, so
		assert back != set1
		// create new set of with sorted objects
		objs := [Integer.from_i64(4), Integer.from_i64(55), Integer.from_i64(666)]
		mut set2 := Set.new()
		set2.add_multi(objs)

		assert back == set2
	}
}
*/
