## asn1
Pure V module for handling Abstract Syntax Notation One (ASN.1) [[X.680]](http://www.itu.int/rec/T-REC-X.680/en) objects encoded in Distinguished Encoding Rules (DER) [[X.690]](https://www.itu.int/rec/T-REC-X.690/en) encoding scheme.

> [!CAUTION]
> This module is marked as an experimental, so, its a subject to change (even rapidly).
> Use it with caution, submit when found a bug and gives yours feedback and review.

## tag handling
- support handling short or long form (multibyte tag), but its sizes was limited to defined constant, `max_tag_length = 3` bytes long.
- support almost popular basic type (except for a few types)

## limitation
- This module is written in DER encoding in mind, with limited support with BER, so maybe if you use BER would be dropped into error.
