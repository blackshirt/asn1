enum ErrorKind {
	// vfmt off
	invalid_tag_class 		= 0
	invalid_tag_form 		= 1
	invalid_tag_number 		= 2
	invalid_tag_format		= 4
	unknown_tag_number		= 5
	bytes_count_exceed		= 3
	invalid_length_value	= 6
	length_exceed_limit		= 7
	unknown_error 			= 8
	number_exceed_limit		= 9
	too_short_data			= 10
	invalid_offset			= 11
	offset_exceed_limit		= 12
	unsupported_rule		= 13
	unsupported_format		= 14
	invalid_value			= 15
	unmeet_requirement		= 16
	// vfmt on
}

fn (ek ErrorKind) str() string {
	match ek {
		.invalid_tag_class { return 'invalid_tag_class' }
		.invalid_tag_form { return 'invalid_tag_form' }
		.invalid_tag_number { return 'invalid_tag_number' }
		.invalid_tag_format { return 'invalid_tag_format' }
		.unknown_tag_number { return 'unknown_tag_number' }
		.bytes_count_exceed { return 'bytes_count_exceed' }
		.invalid_length_value { return 'invalid_length_value' }
		.length_exceed_limit { return 'length_exceed_limit' }
		.unknown_error { return 'unknown_error' }
		.number_exceed_limit { return 'number_exceed_limit' }
		.too_short_data { return 'too_short_data' }
		.invalid_offset { return 'invalid_offset' }
		.offset_exceed_limit { return 'offset_exceed_limit' }
		.unsupported_rule { return 'unsupported_rule' }
		.unsupported_format { return 'unsupported_format' }
		.invalid_value { return 'invalid_value' }
		.unmeet_requirement { return 'unmeet_requirement' }
	}
}

struct Asn1Error {
	Error
	kind   ErrorKind
	object string
	exact  string
	expect string
}

fn (er Asn1Error) msg() string {
	msg := 'Error on ${er.object}: ${er.kind.str()} get: ${er.exact}, expected: ${er.expect}'
	return msg
}

fn asn1_error(kind ErrorKind, obj string, exact string, expect string) &Asn1Error {
	return &Asn1Error{
		kind:   kind
		object: obj
		exact:  exact
		expect: expect
	}
}
