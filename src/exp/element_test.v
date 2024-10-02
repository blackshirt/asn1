module asn1

type MyOct = string

fn (mo MyOct) tag() Tag {
	return Tag{.universal, false, u32(int(TagType.octetstring))}
}

fn (mo MyOct) payload() ![]u8 {
	return mo.bytes()
}

type MyStr = string

fn (ms MyStr) tag() Tag {
	return Tag{.universal, false, u32(int(TagType.utf8string))}
}

fn (ms MyStr) payload() ![]u8 {
	return ms.bytes()
}

struct TestStruct {
	a MyOct
	b MyStr
}

fn (t TestStruct) tag() Tag {
	return Tag{.universal, true, u32(int(TagType.sequence))}
}

fn test_struct_payload() ! {
	st := TestStruct{
		a: MyOct('aku')
		b: MyStr('dia')
	}
	pld := payload[TestStruct](st)!
	dump(pld)
}
