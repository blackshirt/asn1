This file contains examples on about how to use this `asn1` module to write your ASN.1 element, how to serialize it and write routines
how to decode it. Its contains 3 examples, ie:

- `example_0.v` contains sample to write simple thing for some parts of Kerberos Network Authentication protocol parser, how to define your structure based on the ASN.1 Schema, use tagged field for wrapping element, etc.
- `example_1.v` contains sample from already availables on the internet world, taken from https://www.oss.com/asn1/resources/asn1-made-simple/asn1-quick-reference/sequence.html. Its contains more complex structure, write decoder for that structure.
- `example_2.v` contains samples encoding for DER mode comes from `ITU X.690 Document`, Especially from Annex A. Example of encodings of the document.
  But, it not finished yet.
