import sys
__py3__ = sys.version_info[0] is 3

import binascii
import unittest

import cryptu.hash
import cryptu.random

# Just some simple Py3/Py2 cross-compat.
try:
    range = xrange # For python < 3.0
except NameError:
    pass


class TestHash(unittest.TestCase):
    """
    """
    sha1vals = {
        'value':'f32b67c7e26342af42efabc674d441dca0a281c5',
        'foo':'0beec7b5ea3f0fdbc95d0dd47f3c5bc275da8a33'
    }

    sha256vals = {
        'value': 'cd42404d52ad55ccfa9aca4adc828aa5800ad9d385a0671fbcbf724118320619',
        'foo': '2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae'
    }

    sha512vals = {
        'value': 'ec2c83edecb60304d154ebdb85bdfaf61a92bd142e71c4f7b25a15b9cb5f3c0ae301cfb3569cf240e4470031385348bc296d8d99d09e06b26f09591a97527296',
        'foo': 'f7fbba6e0636f890e56fbbf3283e524c6fa3204ae298382d624741d0dc6638326e282c41be5e4254d8820772c5518a2c5a8c0c7f7eda19594a7eb539453e1ed7'
    }

    shashvals = {
        'value': 'a2bfd672d823012c89cfe7e3f283b348b0ed1d3acf94dd8d79ac67b26adac28110cb0a2636b7e002e7530851aed4b681e4cb83eff4b7f7d612577fed1c14ed7c',
        'foo': '19190f2a9aca39a446de586aa8519c2f4687c161c1fc84d528feb8a1e62c5f907f87f834d56e8ccb92736a5d7bf43cb2f28943279c3206d2ab0036df1305b577'
    }

    def test_algs(self):
        for k, v in self.sha1vals.items():
            d = cryptu.hash.sha1.new(k.encode()).digest()
            self.assertEqual(len(d), 20)
            self.assertEqual(binascii.hexlify(d), v.encode())

        for k, v in self.sha256vals.items():
            d = cryptu.hash.sha256.new(k.encode()).digest()
            self.assertEqual(len(d), 32)
            self.assertEqual(binascii.hexlify(d), v.encode())

        for k, v in self.sha512vals.items():
            d = cryptu.hash.sha512.new(k.encode()).digest()
            self.assertEqual(len(d), 64)
            self.assertEqual(binascii.hexlify(d), v.encode())

    def test_timed_serializer(self):
        """
        """
        pass

    def test_shash(self):
        for k, v in self.shashvals.items():
            d = cryptu.hash.shash(k.encode()).digest()
            self.assertEqual(len(d), 64)

            self.assertEqual(binascii.hexlify(d), v.encode())


class TestRandom(unittest.TestCase):
    """
    """
    def test_crypto_random(self):
        for i in range(256):
            rnd = cryptu.random.read(i)
            if __py3__:
                self.assertIsInstance(rnd, bytes)
            else:
                self.assertIsInstance(rnd, str)
            self.assertEqual(len(rnd), i)