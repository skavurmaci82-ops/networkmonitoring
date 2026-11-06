import unittest
from vendors import lookup, parse_ieee


class VendorTests(unittest.TestCase):
    def test_ieee_csv_lookup_and_locally_administered_mac(self):
        registry=parse_ieee(b'Registry,Assignment,Organization Name,Organization Address\nMA-L,000B86,Aruba Networks,Test address\n')
        self.assertEqual(lookup(['00:0B:86:00:12:34'],registry),'Aruba Networks')
        self.assertEqual(lookup(['02:0B:86:00:12:34'],registry),'')
        self.assertEqual(lookup(['not-mac'],registry),'')

    def test_invalid_or_empty_registry_is_rejected(self):
        for value in [b'<html>Denied</html>',b'Assignment,Organization Name\nnot-prefix,Fake\n']:
            with self.assertRaises(ValueError):
                parse_ieee(value)


if __name__=='__main__':
    unittest.main()
