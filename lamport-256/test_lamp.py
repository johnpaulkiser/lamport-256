import unittest


import lamp 
from hashlib import sha256



class TestKeyPairGeneration(unittest.TestCase):
    def setUp(self):
        self.keypair = lamp.generate_keys()

    def test_creates_pub_field_name(self):
        self.assertTrue('pub' in self.keypair)

    def test_creates_priv_field_name(self):
        self.assertTrue('priv' in self.keypair)
    
    def test_priv_key_length_is_2(self): 
        self.assertEqual(len(self.keypair['priv']), 2)

    def test_priv_key_length_is_2(self): 
        self.assertEqual(len(self.keypair['pub']), 2)

    def test_priv_key_0_segment_length_is_256(self):
        self.assertEqual(len(self.keypair['priv'][0]), 256)

    def test_priv_key_1_segment_length_is_256(self):
        self.assertEqual(len(self.keypair['priv'][0]), 256)

    def test_pub_key_0_segment_length_is_256(self):
        self.assertEqual(len(self.keypair['pub'][0]), 256)

    def test_pub_key_1_segment_length_is_256(self):
        self.assertEqual(len(self.keypair['pub'][0]), 256)

    def test_pub_and_priv_match(self):
        priv = self.keypair['priv'][0] + self.keypair['priv'][1]
        pub = self.keypair['pub'][0] + self.keypair['pub'][1]
        hashed_priv = [sha256(block.encode()).hexdigest() for block in priv]
        self.assertEqual(pub, hashed_priv)

class TestSignature(unittest.TestCase):
    def setUp(self):
        self.keypair = lamp.generate_keys()


class TestUtils(unittest.TestCase):
   
    def test_hex_to_binary_converter(self):
        hexstring = 'e9'
        res = lamp.hex_to_bin_list(hexstring)
        self.assertEqual(res, [1, 1, 1, 0, 1, 0, 0, 1])

    def test_hex_to_binary_is_correct_length_8(self):
        hexstring = 'e9'
        res = lamp.hex_to_bin_list(hexstring)
        self.assertEqual(len(res), len(hexstring)*4)

    def test_hex_to_binary_is_correct_length_24(self):
        hexstring = 'e9aa03'
        res = lamp.hex_to_bin_list(hexstring)
        self.assertEqual(len(res), len(hexstring)*4)


if __name__ == '__main__':
    unittest.main()
