import unittest
from hight import *


class TestModularOperations(unittest.TestCase):
    def test_mod_sum(self):
        self.assertEqual(mod_sum(100, 50), 22)
        self.assertEqual(mod_sum(64, 64), 0)
        self.assertEqual(mod_sum(10, 20), 30)

    def test_mod_sub(self):
        self.assertEqual(mod_sub(50, 30), 20)
        self.assertEqual(mod_sub(10, 20), 118)
        self.assertEqual(mod_sub(0, 1), 127)


class TestRotationOperations(unittest.TestCase):
    def test_rol(self):
        self.assertEqual(rol(0b1000000, 1), 0b0000001)
        self.assertEqual(rol(0b0000001, 1), 0b0000010)
        self.assertEqual(rol(0b1010101, 1), 0b0101011)

    def test_F0(self):
        result = F0(0b1010101)
        self.assertIsInstance(result, int)
        self.assertGreaterEqual(result, 0)
        self.assertLess(result, 2**BITS)

    def test_F1(self):
        result = F1(0b1010101)
        self.assertIsInstance(result, int)
        self.assertGreaterEqual(result, 0)
        self.assertLess(result, 2**BITS)


class TestKeyGeneration(unittest.TestCase):
    def test_GenerateRoundKeys(self):
        Key = [i for i in range(16)]
        WK, SK = GenerateRoundKeys(Key)

        self.assertEqual(len(WK), 8)
        self.assertEqual(len(SK), 128)

        for wk in WK:
            self.assertGreaterEqual(wk, 0)
            self.assertLess(wk, 2**BITS)

        for sk in SK:
            self.assertGreaterEqual(sk, 0)
            self.assertLess(sk, 2**BITS)


class TestBlockEncryption(unittest.TestCase):
    def setUp(self):
        self.key = [ord(c) % (2**BITS) for c in "abcdefghijklmnop"]
        self.plaintext = [1, 2, 3, 4, 5, 6, 7, 8]

    def test_EncryptBlock(self):
        ciphertext = EncryptBlock(self.plaintext, self.key)
        decrypted = DecryptBlock(ciphertext, self.key)

        self.assertEqual(len(ciphertext), 8)
        self.assertEqual(len(decrypted), 8)
        self.assertEqual(self.plaintext, decrypted)

        for byte in ciphertext:
            self.assertGreaterEqual(byte, 0)
            self.assertLess(byte, 2**BITS)


class TestDataEncryption(unittest.TestCase):
    def setUp(self):
        self.key = [ord(c) % (2**BITS) for c in "abcdefghijklmnop"]

    def test_encrypt_decrypt_block(self):
        data = [1, 2, 3, 4, 5, 6, 7, 8]
        encrypted = EncryptData(data, self.key)
        decrypted = DecryptData(encrypted, self.key)

        self.assertEqual(data, decrypted)

    def test_encrypt_decrypt(self):
        data = [i % (2**BITS) for i in range(24)]
        encrypted = EncryptData(data, self.key)
        decrypted = DecryptData(encrypted, self.key)

        self.assertEqual(data, decrypted)

    def test_encrypt_decrypt_partial_block(self):
        data = [1, 2, 3, 4, 5]
        encrypted = EncryptData(data, self.key)
        decrypted = DecryptData(encrypted, self.key)

        self.assertEqual(data, decrypted[: len(data)])

    def test_encrypt_decrypt_text(self):
        text = "Perspiciatis omnis laborum harum sapiente voluptatem sit vel."
        data = [ord(c) % (2**BITS) for c in text]

        encrypted = EncryptData(data, self.key)
        decrypted = DecryptData(encrypted, self.key)

        self.assertEqual(data, decrypted[: len(data)])

    def test_invalid_encrypted_data_length(self):
        invalid_data = [1, 2, 3, 4, 5]

        with self.assertRaises(ValueError) as context:
            DecryptData(invalid_data, self.key)

        self.assertIn("Encrypted data length is wrong", str(context.exception))


class TestVectors(unittest.TestCase):
    def test_key_and_plaintext(self):
        K_str = "abcdefghijklmnop"
        K = [ord(c) % (2**BITS) for c in K_str]

        Data_str = "Perspiciatis omnis laborum harum sapiente voluptatem sit vel."
        Data = [ord(c) % (2**BITS) for c in Data_str]

        EncryptedData = EncryptData(Data, K)
        DecryptedData = DecryptData(EncryptedData, K)

        self.assertEqual(Data, DecryptedData[: len(Data)])
    
    def test_1(self):
        K = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]
        P = [0x00] * 8

        self.assertEqual(EncryptBlock(P, K), [0x00, 0xf4, 0x18, 0xae, 0xd9, 0x4f, 0x03, 0xf2])

    def test_2(self):
        K = [0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00]
        P = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77]

        self.assertEqual(EncryptBlock(P, K), [0x23, 0xce, 0x9f, 0x72, 0xe5, 0x43, 0xe6, 0xd8])

    def test_3(self):
        K = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f]
        P = [0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef]

        self.assertEqual(EncryptBlock(P, K), [0x7a, 0x6f, 0xb2, 0xa2, 0x8d, 0x23, 0xf4, 0x66])

    def test_4(self):
        K = [0x28, 0xdb, 0xc3, 0xbc, 0x49, 0xff, 0xd8, 0x7d, 0xcf, 0xa5, 0x09, 0xb1, 0x1d, 0x42, 0x2b, 0xe7]
        P = [0xb4, 0x1e, 0x6b, 0xe2, 0xeb, 0xa8, 0x4a, 0x14]

        self.assertEqual(EncryptBlock(P, K), [0xcc, 0x04, 0x7a, 0x75, 0x20, 0x9c, 0x1f, 0xc6])


class TestEdgeCases(unittest.TestCase):
    def setUp(self):
        self.key = [i for i in range(16)]

    def test_all_zeros_plaintext(self):
        plaintext = [0] * 8
        ciphertext = EncryptBlock(plaintext, self.key)
        decrypted = DecryptBlock(ciphertext, self.key)

        self.assertEqual(plaintext, decrypted)

    def test_all_max_plaintext(self):
        plaintext = [2**BITS - 1] * 8
        ciphertext = EncryptBlock(plaintext, self.key)
        decrypted = DecryptBlock(ciphertext, self.key)

        self.assertEqual(plaintext, decrypted)

    def test_empty_data(self):
        data = []
        encrypted = EncryptData(data, self.key)
        self.assertEqual(len(encrypted), 0)


if __name__ == "__main__":
    unittest.main()
