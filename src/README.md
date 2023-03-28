## asn1
Pure V module for handling Abstract Syntax Notation One (ASN.1) [X.680] objects encoded in Distinguished Encoding Rules (DER) encoding scheme.

# tag handling
- support handling short or long form (multibyte tag), but its limited to defined constant, `max_tag_bytes_length = 5`
- support almost popular basic type (except for a few types)

# limitation
- only support DER encoding
