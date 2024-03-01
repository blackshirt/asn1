asn1.new(et ElementType) !Element
asn1.Element.pack(to=.der) ![]u8
asn2.Element.unpack(b []u8, mode=.der) !Element
asn1.Element.new(et ElementType) !Element