module asn1

type MyOct = string

fn (mo MyOct) tag() Tag {
	return Tag{.universal, false, u32(int(TagType.octetstring))} // 0x04
}

fn (mo MyOct) payload() ![]u8 {
	return mo.bytes()
}

type MyStr = string

fn (ms MyStr) tag() Tag {
	return Tag{.universal, false, u32(int(TagType.utf8string))} // 0x12
}

fn (ms MyStr) payload() ![]u8 {
	return ms.bytes()
}

struct TestStruct {
	n int
	a MyOct
	b MyStr
}

fn (t TestStruct) tag() Tag {
	return Tag{.universal, true, u32(int(TagType.sequence))} // 0x30
}

fn (t TestStruct) payload() ![]u8 {
	out := build_payload[TestStruct](t)!
	return out
}

fn test_struct_build_payload() ! {
	st := TestStruct{
		a: MyOct('aku')
		b: MyStr('dia')
	}
	// TestStruct is sequence
	out := encode(st)!
	expected := [u8(0x30), 0x0a, (0x04), 0x03, 0x61, 0x6b, 0x75, (0x0c), 0x03, 0x64, 0x69, 0x61]
	// without field option passed, its should be expected value
	assert out == expected
}
