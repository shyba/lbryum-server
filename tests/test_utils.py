__author__ = 'erasmospunk'

import unittest
from lbryumserver.utils import hash_160_to_address, bc_address_to_hash_160


class UtilTest(unittest.TestCase):
    def test_hash_160_to_address(self):
        self.assertEqual(hash_160_to_address(None), None)
        self.assertEqual(hash_160_to_address('27e8a203f2'.decode('hex')), None)
        self.assertEqual(hash_160_to_address('27e8a203f20080826434c8667bb060e80c3ef9fb1337'.decode('hex')), None)
        self.assertEqual(hash_160_to_address('27e8a203f20080826434c8667bb060e80c3ef9fb'.decode('hex')),
                         'bGNHjKwxD5pu9ppmLYrVxkR3ahz2C8oHZM')

    def test_bc_address_to_hash_160(self):
        self.assertEqual(bc_address_to_hash_160(None), None)
        self.assertEqual(bc_address_to_hash_160(''), None)
        self.assertEqual(bc_address_to_hash_160('bGNHjKwxD5pu9ppmLYrVxkR3ahz2C8oHZM1337'), None)
        self.assertEqual(bc_address_to_hash_160('bGNHjKwxD5pu9ppmLYrVxkR3ahz2C8oHZM').encode('hex'),
                         '27e8a203f20080826434c8667bb060e80c3ef9fb')


if __name__ == '__main__':
    unittest.main()
