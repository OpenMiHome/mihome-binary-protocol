#!/usr/bin/env python3
"""Xiaomi MiHome Binary protocol.

This module supports the encrypted Xiaomi MiHome protocol.
https://github.com/ximihobi

(c) 2016-2017 Wolfgang Frisch

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
"""

import struct
import hashlib

# https://cryptography.io/
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
_backend = default_backend()


def md5(inp: bytes) -> bytes:
    m = hashlib.md5()
    m.update(inp)
    return m.digest()


def key_iv(token: bytes) -> (bytes, bytes):
    """Derive (Key, IV) from a Xiaomi MiHome device token (128 bits)."""
    key = md5(token)
    iv = md5(key + token)
    return (key, iv)


def AES_cbc_encrypt(token: bytes, plaintext: bytes) -> bytes:
    """Encrypt plain text with device token."""
    key, iv = key_iv(token)
    padder = padding.PKCS7(128).padder()
    padded_plaintext = padder.update(plaintext)
    padded_plaintext += padder.finalize()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=_backend)
    encryptor = cipher.encryptor()
    return encryptor.update(padded_plaintext) + encryptor.finalize()


def AES_cbc_decrypt(token: bytes, ciphertext: bytes) -> bytes:
    """Decrypt cipher text with device token."""
    key, iv = key_iv(token)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=_backend)
    decryptor = cipher.decryptor()
    padded_plaintext = decryptor.update(bytes(ciphertext)) \
        + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    unpadded_plaintext = unpadder.update(padded_plaintext)
    unpadded_plaintext += unpadder.finalize()
    return unpadded_plaintext


def print_head(raw_packet: bytes):
    """Print the header fields of a MiHome packet."""
    head = raw_packet[:32]
    magic, packet_len, unknown1, did, stamp, md5 = \
        struct.unpack('!2sHIII16s', head)
    print("  magic:        %8s" % magic.hex())
    print("  packet_len:   %8x" % packet_len)
    print("  unknown field:     %8x" % unknown1)
    print("  device ID:     %8x" % did)
    print("  stamp:        %8x" % stamp)
    print("  md5 checksum: %s" % md5.hex())


def encrypt(stamp: int, did: int, token: bytes, plaindata: bytes) -> bytes:
    """Generate an encrypted packet from plain data.

    Args:
        stamp: incrementing counter
        token: 128 bit device token
        plaindata: plain data
    """
    def init_msg_head(stamp: int, did: int, token: bytes, packet_len: int) -> bytes:
        head = struct.pack(
            '!BBHIII16s',
            0x21, 0x31,  # const magic value
            packet_len,
            0,  # unknown const
            did,  # device id
            stamp,
            token  # overwritten by the MD5 checksum later
        )
        return head

    payload = AES_cbc_encrypt(token, plaindata)
    packet_len = len(payload) + 32
    packet = bytearray(init_msg_head(stamp, did, token, packet_len) + payload)
    checksum = md5(packet)
    for i in range(0, 16):
        packet[i+16] = checksum[i]
    return packet


def decrypt(token: bytes, cipherpacket: bytes) -> bytes:
    """Decrypt a packet.

    Args:
        token: 128 bit device token
        cipherpacket: packet data
    """
    ciphertext = cipherpacket[32:]
    plaindata = AES_cbc_decrypt(token, ciphertext)
    return plaindata


class MiioPacket():
    def __init__(self):
        self.magic = (0x21, 0x31)
        self.length = None
        self.unknown1 = 0
        self.did = 0
        self.stamp = 0
        self.data = None
        self.md5 = None

    def read(self, raw: bytes):
        """Parse the payload of a UDP packet."""
        head = raw[:32]
        self.magic, self.length, self.unknown1, \
        self.did, self.stamp, self.md5 = \
            struct.unpack('!2sHIII16s', head)
        self.data = raw[32:]

    def generate(self, token: bytes) -> bytes:
        """Generate an encrypted packet."""
        return encrypt(self.stamp, token, self.data)        

# vim:set expandtab tabstop=4 shiftwidth=4 softtabstop=4 nowrap:
