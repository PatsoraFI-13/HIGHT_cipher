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


class TestKnownVectors(unittest.TestCase):
    def test_key_and_plaintext(self):
        K_str = "abcdefghijklmnop"
        K = [ord(c) % (2**BITS) for c in K_str]

        Data_str = "Perspiciatis omnis laborum harum sapiente voluptatem sit vel."
        Data = [ord(c) % (2**BITS) for c in Data_str]

        EncryptedData = EncryptData(Data, K)
        DecryptedData = DecryptData(EncryptedData, K)

        self.assertEqual(Data, DecryptedData[: len(Data)])


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
