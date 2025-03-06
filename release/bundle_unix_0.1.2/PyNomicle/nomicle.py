#!/usr/bin/env python3

# pynomicle.py | v0.1 | 23/08/2019 | by alimahouk
# -----------------------------------------------
# ABOUT THIS FILE
# -----------------------------------------------
# This file contains shared data structures and classes.
# It is a dependency and is not meant to be executed directly.

import hashlib
import os
import random
import time
if os.name == "nt":
        from ctypes import windll, wintypes, byref
from datetime import datetime

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.hazmat.primitives.serialization import load_der_public_key


class IdentityBlock():
        # IDENTITY BLOCK STRUCTURE
        ##########################
        # 1) MAGIC NUMBER
        # ------------------------------------
        # 2) IDENTITY VERSION (1 byte)
        # ------------------------------------
        # 3) BLOCK HASH (8 bytes)
        #-------------------------------------
        # 4) SIGNATURE SIZE (2 bytes)
        #-------------------------------------
        # 5) SIGNATURE
        #-------------------------------------
        # 6) IDENTITY TOKEN HASH (32 bytes)
        #-------------------------------------
        # 7) BITS (TARGET) (4 bytes)
        #-------------------------------------
        # 8) NONCE (8 bytes)
        #-------------------------------------
        # 9) EXTRA NONCE (8 bytes)
        #-------------------------------------
        # 10) TIMESTAMP CREATED (8 bytes)
        #-------------------------------------
        # 11) TIMESTAMP UPDATED (8 bytes)
        #-------------------------------------
        # 12) PUBLIC KEY SIZE (2 bytes)
        #-------------------------------------
        # 13) PUBLIC KEY
        
        BITS_BASE = 0x1f00ffff
        ID_VERSION = 0
        MAGIC_NUM = bytearray([0x89, 0x50, 0x44, 0x48, 0x5a, 0x0d, 0x0a, 0x1a, 0x0a])
        TARGET_DECREASE_PERCENTAGE = 1

        def __init__(self, identifier=None, publicKey=None):
                if identifier is not None and len(identifier) > 0:
                        self.identifier = hashlib.sha256(identifier.encode() if isinstance(identifier, str) else identifier).digest()
                else:
                        self.identifier = None

                self.bits = self.BITS_BASE # Start at the highest possible target (difficulty 1, 0x1d00ffff) by default.
                self.blockHash = None
                self.extraNonce = 0
                self.nonce = 0
                self.publicKey = publicKey
                self.signature = None
                self.timestampCreated = datetime.now()
                self.timestamUpdated = datetime.now()
                self.version = self.ID_VERSION
        
        def __eq__(self, other):
                if isinstance(other, IdentityBlock) and \
                   self.blockHash == other.blockHash:
                        return True
                else:
                        return False
        
        def __hash__(self):
                return hash(self.blockHash)

        def __repr__(self):
                return f"<IdentityBlock: {self.identifier.hex()}>"

        def __str__(self):
                return f"<IdentityBlock: {self.identifier.hex()}>"

        @staticmethod
        def compare(block1, block2):
                # These return a tuple. The target is the third item.
                unpack1 = block1.unpackTarget()
                unpack2 = block2.unpackTarget()
                if unpack1[2] == unpack2[2]:
                        return 0
                elif unpack1[2] < unpack2[2]:
                        return -1
                else:
                        return 1

        @staticmethod
        def deserialise(blockByteArray):
                if blockByteArray is None:
                        raise ValueError("IdentityBlock.deserialise(1): blockByteArray is None")

                # 1) Magic number
                if blockByteArray[:len(IdentityBlock.MAGIC_NUM)] != IdentityBlock.MAGIC_NUM:
                        raise Exception("IdentityBlock.deserialise(1): invalid magic number!")

                block = IdentityBlock()
                offset = len(IdentityBlock.MAGIC_NUM)
                # 2) Protocol version (1 byte)
                block.version = int.from_bytes(
                        blockByteArray[offset:offset+1], 
                        byteorder="big", 
                        signed=False
                        )
                offset += 1
                # 3) Block hash (8 bytes)
                block.blockHash = bytes(blockByteArray[offset:offset+8])
                offset += 8
                # 4) Signature size (2 bytes)
                signatureSize = int.from_bytes(
                        blockByteArray[offset:offset+2], 
                        byteorder="big", 
                        signed=False
                        )
                offset += 2
                # 5) Signature
                if signatureSize > 0:
                        block.signature = bytes(blockByteArray[offset:offset+signatureSize])
                else:
                        block.signature = None
                offset += signatureSize
                # 6) Identity token hash (32 bytes)
                block.identifier = bytes(blockByteArray[offset:offset+32])
                offset += 32
                # 7) Bits (4 bytes)
                block.bits = int.from_bytes(
                        blockByteArray[offset:offset+4], 
                        byteorder="big", 
                        signed=False
                        )
                offset += 4
                # 8) Nonce (8 bytes)
                block.nonce = int.from_bytes(
                        blockByteArray[offset:offset+8], 
                        byteorder="big", 
                        signed=False
                        )
                offset += 8
                # 9) Extra nonce (8 bytes)
                block.extraNonce = int.from_bytes(
                        blockByteArray[offset:offset+8], 
                        byteorder="big", 
                        signed=False
                        )
                offset += 8
                # 10) Timestamp Created (8 bytes)
                timeCreated = int.from_bytes(
                        blockByteArray[offset:offset+8], 
                        byteorder="big", 
                        signed=True
                        )
                block.timestampCreated = datetime.fromtimestamp(timeCreated)
                offset += 8
                # 11) Timestamp Updated (8 bytes)
                timeUpdated = int.from_bytes(
                        blockByteArray[offset:offset+8], 
                        byteorder="big", 
                        signed=True
                        )
                block.timestampUpdated = datetime.fromtimestamp(timeUpdated)
                offset += 8
                # 12) Public key size (2 bytes)
                publicKeySize = int.from_bytes(
                        blockByteArray[offset:offset+2], 
                        byteorder="big", 
                        signed=False
                        )
                offset += 2
                # 13) Public key
                block.publicKey = load_der_public_key(bytes(blockByteArray[offset:offset+publicKeySize]), backend=default_backend())
                offset += publicKeySize
                # Check if the key is a valid EC public key.
                if not isinstance(block.publicKey, ec.EllipticCurvePublicKey):
                        raise TypeError("IdentityBlock.deserialise(1): invalid EC public key!")

                # Verify the hash. Remeber that only the first 8 bytes are actually stored.
                blockDigest = block.hash()
                if blockDigest[:8] != block.blockHash:
                        raise Exception("IdentityBlock.deserialise(1): invalid block hash!")
                
                # Verify the signature.
                try:
                        block.publicKey.verify(
                                block.signature, 
                                blockDigest, 
                                ec.ECDSA(utils.Prehashed(hashes.SHA256()))
                                )
                except InvalidSignature:
                        raise Exception("IdentityBlock.deserialise(1): invalid block signature!")
                
                return block

        def dump(self, path, privateKey=None):
                blockByteArray = bytes(self.serialise(privateKey))

                with open(path, mode="w+b") as newFile:
                        newFile.write(blockByteArray)
                # Add some useful file metadata.
                timestampCreatedSeconds = self.timestampCreated.timestamp()
                timestampUpdatedSeconds = self.timestampUpdated.timestamp()
                # Unfortunately, only Windows has calls that allow for setting file creation time.
                if os.name == "nt":
                        # Windows requires special calls.
                        # Convert Unix timestamp to Windows FileTime using some magic numbers.
                        # See documentation: https://support.microsoft.com/en-us/help/167296
                        timestamp = int((timestampCreatedSeconds * 10000000) + 116444736000000000)
                        ctime = wintypes.FILETIME(timestamp & 0xffffffff, timestamp >> 32)
                        # Call Win32 API to modify the file creation date.
                        handle = windll.kernel32.CreateFileW(str(path), 256, 0, None, 3, 128, None)
                        windll.kernel32.SetFileTime(handle, byref(ctime), None, None)
                        windll.kernel32.CloseHandle(handle)
                
                os.utime(path, (timestampUpdatedSeconds, timestampUpdatedSeconds))
        
        # This method does not modify the nonce. It has to be manually
        # incremented.
        def hash(self):
                # We pack everything from the block into a buffer
                # excluding the magic number, signature,
                # and the hash itself (obviously).

                # 1) Protocol version
                versionBytes = self.version.to_bytes(
                        1, 
                        byteorder="big", 
                        signed=False
                        )
                buffer = bytearray(versionBytes)
                # 2) Identity token hash
                buffer.extend(self.identifier)
                # 3) Bits
                bitsBytes = self.bits.to_bytes(
                        4, 
                        byteorder="big", 
                        signed=False
                        )
                buffer.extend(bitsBytes)
                # 4) Nonce
                nonceBytes = self.nonce.to_bytes(
                        8, 
                        byteorder="big", 
                        signed=False
                        )
                buffer.extend(nonceBytes)
                # 5) Extra nonce
                extraNonceBytes = self.extraNonce.to_bytes(
                        8, 
                        byteorder="big", 
                        signed=False
                        )
                buffer.extend(extraNonceBytes)
                # 6) Timestamp Created
                timeCreated = int(self.timestampCreated.timestamp())
                timeCreatedBytes = timeCreated.to_bytes(
                        8, 
                        byteorder="big", 
                        signed=True
                        )
                buffer.extend(timeCreatedBytes)
                # 7) Timestamp Updated
                timeUpdated = int(self.timestampUpdated.timestamp())
                timeUpdatedBytes = timeUpdated.to_bytes(
                        8, 
                        byteorder="big", 
                        signed=True
                        )
                buffer.extend(timeUpdatedBytes)
                # 8) Public key size
                publicKeyBytes = self.publicKey.public_bytes(
                        encoding=serialization.Encoding.DER,
                        format=serialization.PublicFormat.SubjectPublicKeyInfo
                        )
                publicKeySize = len(publicKeyBytes)
                publicKeySizeBytes = publicKeySize.to_bytes(
                        2, 
                        byteorder="big", 
                        signed=False
                        )
                buffer.extend(publicKeySizeBytes)
                # 9) Public key
                buffer.extend(publicKeyBytes)

                return hashlib.sha256(buffer).digest()
        
        @staticmethod
        def lowerTarget(bits):
                exponent = (bits >> (8 * 3)) & 0xff
                mantissa = (bits >> (8 * 0)) & 0xffffff
                target = mantissa * (2**(0x08 * (exponent - 0x03)))
                
                percentage = int(target * (IdentityBlock.TARGET_DECREASE_PERCENTAGE / 100))
                exponent = 3
                target -= percentage

                isSigned = (target < 0)

                if isSigned:
                        target *= -1

                while target > 0x7fffff:
                        target >>= 8
                        exponent += 1

                if (target & 0x00800000) > 0:
                        target >>= 8
                        exponent += 1

                result = ((exponent << 24) + target)

                if isSigned:
                        result = result | 0x00800000

                return result

        @staticmethod
        def read(path):
                try:
                        with open(path, mode="rb") as file:
                                blockByteArray = bytearray(file.read())
                                return IdentityBlock.deserialise(blockByteArray)
                except EnvironmentError:
                        return None

        def serialise(self, privateKey=None):
                if privateKey is not None:
                        # Calculate a hash of the block, store it within,
                        # then sign it.
                        blockDigest = self.hash()
                        self.blockHash = blockDigest[:8]
                        self.signature = IdentityBlock.sign(blockDigest, privateKey)

                # 1) Magic number
                blockByteArray = bytearray(self.MAGIC_NUM)
                # 2) Protocol version
                versionBytes = self.version.to_bytes(
                        1, 
                        byteorder="big", 
                        signed=False
                        )
                blockByteArray.extend(versionBytes)
                # 3) Block hash (first 8 bytes only)
                if self.blockHash is not None:
                        blockByteArray.extend(self.blockHash[:8])
                else:
                        blockByteArray.extend([0] * 8)
                # 4) Signature size
                if self.signature is not None:
                        signatureBytes = self.signature
                        signatureSize = len(signatureBytes)
                else:
                        signatureBytes = None
                        signatureSize = 0
                signatureSizeBytes = signatureSize.to_bytes(
                        2, 
                        byteorder="big", 
                        signed=False
                        )
                blockByteArray.extend(signatureSizeBytes)
                # 5) Signature
                if signatureBytes is not None:
                        blockByteArray.extend(signatureBytes)
                # 6) Identity token hash
                blockByteArray.extend(self.identifier)
                # 7) Bits
                bitsBytes = self.bits.to_bytes(
                        4, 
                        byteorder="big", 
                        signed=False
                        )
                blockByteArray.extend(bitsBytes)
                # 8) Nonce
                nonceBytes = self.nonce.to_bytes(
                        8, 
                        byteorder="big", 
                        signed=False
                        )
                blockByteArray.extend(nonceBytes)
                # 9) Extra nonce
                extraNonceBytes = self.extraNonce.to_bytes(
                        8, 
                        byteorder="big", 
                        signed=False
                        )
                blockByteArray.extend(extraNonceBytes)
                # 10) Timestamp Created
                timeCreated = int(self.timestampCreated.timestamp())
                timeCreatedBytes = timeCreated.to_bytes(
                        8, 
                        byteorder="big", 
                        signed=True
                        )
                blockByteArray.extend(timeCreatedBytes)
                # 11) Timestamp Updated
                timeUpdated = int(self.timestampUpdated.timestamp())
                timeUpdatedBytes = timeUpdated.to_bytes(
                        8, 
                        byteorder="big", 
                        signed=True
                        )
                blockByteArray.extend(timeUpdatedBytes)
                # 12) Public key size
                publicKeyBytes = self.publicKey.public_bytes(
                        encoding=serialization.Encoding.DER,
                        format=serialization.PublicFormat.SubjectPublicKeyInfo
                        )
                publicKeySize = len(publicKeyBytes)
                publicKeySizeBytes = publicKeySize.to_bytes(
                        2, 
                        byteorder="big", 
                        signed=False
                        )
                blockByteArray.extend(publicKeySizeBytes)
                # 13) Public key
                blockByteArray.extend(publicKeyBytes)

                return blockByteArray
        
        # Although the argument is called "blockHash", this method
        # can be used to sign any kind of hash.
        @staticmethod
        def sign(blockHash, privateKey):
                if privateKey is None:
                        raise ValueError("IdentityBlock.sign(2): privateKey is None")
                elif blockHash is None:
                        raise ValueError("IdentityBlock.sign(2): blockHash is None")
                
                signature = privateKey.sign(
                                blockHash,
                                ec.ECDSA(utils.Prehashed(hashes.SHA256()))
                        )
                return signature
        
        def unpackTarget(self):
                exponent = (self.bits >> (8 * 3)) & 0xff
                mantissa = (self.bits >> (8 * 0)) & 0xffffff
                target = mantissa * (2**(0x08 * (exponent - 0x03)))
                return (exponent, mantissa, target)
