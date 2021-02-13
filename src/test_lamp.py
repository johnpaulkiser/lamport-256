import os
import unittest
import lamport_256 as lamp 
from hashlib import sha256
from unittest.mock import patch
from io import StringIO

class TestKeyPairGeneration(unittest.TestCase):

    @classmethod
    def setUpClass(self):
        self.keypair = lamp.generate_keys()

    def test_priv_key_length_is_2(self): 
        self.assertEqual(len(self.keypair.priv), 2)

    def test_priv_key_length_is_2(self): 
        self.assertEqual(len(self.keypair.pub), 2)

    def test_priv_key_0_segment_length_is_256(self):
        self.assertEqual(len(self.keypair.priv[0]), 256)

    def test_priv_key_1_segment_length_is_256(self):
        self.assertEqual(len(self.keypair.priv[0]), 256)

    def test_pub_key_0_segment_length_is_256(self):
        self.assertEqual(len(self.keypair.pub[0]), 256)

    def test_pub_key_1_segment_length_is_256(self):
        self.assertEqual(len(self.keypair.pub[0]), 256)

    def test_pub_and_priv_match(self):
        priv = self.keypair.priv[0] + self.keypair.priv[1]
        pub = self.keypair.pub[0] + self.keypair.pub[1]
        hashed_priv = [sha256(block.encode()).hexdigest() for block in priv]
        self.assertEqual(pub, hashed_priv)


class TestSignature(unittest.TestCase):

    @classmethod
    def setUpClass(self):
        self.keypair = lamp.generate_keys()
        self.priv = self.keypair.priv
        self.pub = self.keypair.pub

    def test_verify_signature_succeeds_on_same_message(self):
        msg = 'a'
        same_msg = 'a'
        signature = lamp.sign_message(self.priv, msg)
        self.assertTrue(lamp.verify_signature(self.pub, msg, signature)) 

    def test_verify_signature_fails_on_different_message(self):
        msg = 'a'
        different_msg = 'b'
        signature = lamp.sign_message(self.priv, msg)
        self.assertFalse(lamp.verify_signature(self.pub, different_msg, signature)) 

    def test_verify_signature_succeeds_on_same_key(self):
        msg = 'test message'
        signature = lamp.sign_message(self.priv, msg)
        self.assertTrue(lamp.verify_signature(self.pub, msg, signature)) 

    def test_verify_signature_fails_on_different_fails(self):
        msg = 'test message'
        signature = lamp.sign_message(self.priv, msg)
        different_pub = lamp.generate_keys().pub
        self.assertFalse(lamp.verify_signature(different_pub, msg, signature)) 

    def test_signature_is_256_blocks_long(self):
        msg = 'test message'
        signature = lamp.sign_message(self.priv, msg)
        self.assertEqual(len(signature), 256) 
    


class TestUtils(unittest.TestCase):

    @classmethod
    def setUpClass(self):
        self.keypair = lamp.generate_keys()
        self.priv = self.keypair.priv
        self.pub = self.keypair.pub

    def tearDown(self):
        filenames = [
            'test_pub.key', 'test_priv.key', 
            'test_pub_inpair.key', 'test_priv_inpair.key'
        ]

        for f in filenames:
            if os.path.exists(f):
                os.remove(f)

    def test_export_pub_key_creates_file(self):
        filename = 'test_pub.key'
        lamp.export_key(key=self.pub, filename=filename)
        self.assertTrue(os.path.exists(filename))

    def test_export_priv_key_creates_file(self):
        filename = 'test_priv.key'
        lamp.export_key(key=self.pub, filename=filename)
        self.assertTrue(os.path.exists(filename))

    def test_export_key_pair_files_exist(self):
        pub_name = 'test_pub_inpair.key'
        priv_name = 'test_priv_inpair.key'
        lamp.export_key_pair(self.keypair, pub_name, priv_name)
        self.assertTrue(os.path.exists(pub_name) and os.path.exists(priv_name))
    
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

    def test_parse_key_is_correct_length(self):
        filename = 'test_priv.key'
        lamp.export_key(self.priv, filename)
        key = lamp.parse_key(filename)
        self.assertEqual(len(key), 2)

    def test_parse_key_zeropart_is_correct_length(self):
        filename = 'test_priv.key'
        lamp.export_key(self.priv, filename)
        key = lamp.parse_key(filename)
        self.assertEqual(len(key[0]), 256)

    def test_parse_key_parts_are_same_length(self):
        filename = 'test_priv.key'
        lamp.export_key(self.priv, filename)
        key = lamp.parse_key(filename)
        self.assertEqual(len(key[0]), len(key[0]))

    
    
class TestCLI(unittest.TestCase):

    def tearDown(self):
        filenames = [
            'pub.key', 'priv.key',
            'test_pub.key', 'test_priv.key', 
            'test_pub_inpair.key', 'test_priv_inpair.key',
            'test_sign.txt', 'test_msg.txt'
        ]

        for f in filenames:
            if os.path.exists(f):
                os.remove(f)

    def test_cli_generates_keys_with_no_flag(self):
        pub_name = 'pub.key'
        priv_name = 'priv.key'
        lamp.cli(['generate_keys'])
        self.assertTrue(os.path.exists(pub_name) and os.path.exists(priv_name))

    def test_cli_generates_keys_with_pub_flag(self):
        pub_name = 'pub.key'
        lamp.cli(['generate_keys', '--pub', pub_name])
        self.assertTrue(os.path.exists(pub_name))

    def test_cli_generates_keys_with_priv_flag(self):
        priv_name = 'priv.key'
        lamp.cli(['generate_keys', '--priv', priv_name])
        self.assertTrue(os.path.exists(priv_name))

    def test_cli_sign_writes_correct_signature_to_stdout(self):
        keypair = lamp.generate_keys()
        msg = 'hey'
        priv_name = 'test_priv.key'
        sig_name = 'test_sign.txt'
        expected_sig = lamp.sign_message(keypair.priv, msg)
        lamp.export_key(keypair.priv, priv_name)
        with patch('sys.stdout', new = StringIO()) as fake_out:
            lamp.cli(['sign', '--priv', priv_name, '--msg', msg]) 
            self.assertEqual(lamp.str_to_sig(fake_out.getvalue()), expected_sig)

    def test_cli_verify_signature_with_inline_msg(self):
        keypair = lamp.generate_keys()
        msg = 'hey'
        pub_name = 'test_pub.key'
        sig_name = 'test_sign.txt'
        sig = lamp.sign_message(keypair.priv, msg)
        lamp.export_key(keypair.pub, pub_name)
        with open(sig_name, 'w') as f:
            f.write(''.join(sig).strip())
        
        with patch('sys.stdout', new = StringIO()) as fake_out:
            lamp.cli(['verify', '--pub', pub_name, '--msg', msg, '--sig', sig_name])
            self.assertEqual(fake_out.getvalue().strip(), 'valid')

    def test_cli_verify_signature_with_msg_from_file(self):
        keypair = lamp.generate_keys()
        msg = 'hey'
        msg_name = 'test_msg.txt'
        pub_name = 'test_pub.key'
        sig_name = 'test_sign.txt'
        sig = lamp.sign_message(keypair.priv, msg)
        lamp.export_key(keypair.pub, pub_name)
        with open(msg_name, 'w') as f:
            f.write(msg)
        with open(sig_name, 'w') as f:
            f.write(''.join(sig).strip())
        
        with patch('sys.stdout', new = StringIO()) as fake_out:
            lamp.cli(['verify', '--pub', pub_name, '--msg', msg_name, '--sig', sig_name])
            self.assertEqual(fake_out.getvalue().strip(), 'valid')


if __name__ == '__main__':
    unittest.main()
