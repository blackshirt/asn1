module asn1

fn test_asn1_attribute_in_options_attrs() {
	options := ['asn1']
	status := attrs_has_asn1_flag(options)

	assert status == true
}

fn test_asn1_attribute_not_in_options_attrs() {
	options := ['application', 'asn1.1']
	status := attrs_has_asn1_flag(options)

	assert status != true
}
