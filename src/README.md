## asn1
Pure V module for handling Abstract Syntax Notation One (ASN.1) [[X.680]](http://www.itu.int/rec/T-REC-X.680/en) objects encoded in Distinguished Encoding Rules (DER) [[X.690]](https://www.itu.int/rec/T-REC-X.690/en) encoding scheme.

## tag handling
- support handling short or long form (multibyte tag), but its sizes was limited to defined constant, `max_tag_bytes_length = 5` bytes long.
- support almost popular basic type (except for a few types)

## limitation
- only support DER encoding
