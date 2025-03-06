#!/usr/bin/env python3

# xtalk.py | v0.1.2 | 23/08/2019 | by alimahouk
# ------------------------------------------------
# ABOUT THIS FILE
# ------------------------------------------------
# This is the Messenger program that is responsible for message
# handling between applications and other instances of Messengers
# running on peers.

import hashlib
import math
import os
import random
import socket
import sys
import time
import threading
import uuid
from binascii import unhexlify
from datetime import datetime, timedelta
from distutils.util import strtobool
from enum import auto, Enum, IntEnum
from pathlib import Path
from statistics import mode 

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import load_der_public_key

from PyNomicle.nomicle import IdentityBlock


#
# CONSTANTS
#
CONF_NCLE_KEY_BLOCK_PATH = "blockpath"
CONF_NCLE_KEY_ID_BLOB = "blob"          # This is a flag used to tell the program whether to treat the identity file in binary mode rather than text.
CONF_NCLE_KEY_ID_PATH = "idpath"
CONF_NCLE_KEY_KEY_PATH = "keypath"
CONF_SYMBOL_COMMENT = "#"
FILE_EXT_NCLE = "ncle"
FILE_EXT_XTALK = "xmsg"
FILE_EXT_XTALK_RECEIPT = "xrct"

if os.name == "nt":
        # In the case of Windows, everything goes in one folder per app.
        PATH_NCLE_DIR_DATA = Path(os.environ["APPDATA"]) / "NCLE"
        PATH_NCLE_DIR_COMMON = Path(os.environ["APPDATA"]) / "NCLE"
        PATH_NCLE_DIR_CONF = Path(os.environ["APPDATA"]) / "NCLE"
        PATH_XTALK_DIR_DATA = Path(os.environ["APPDATA"]) / "xTalk"
        PATH_XTALK_DIR_COMMON = Path(os.environ["APPDATA"]) / "xTalk"
        PATH_XTALK_DIR_CONF = Path(os.environ["APPDATA"]) / "xTalk"

        PATH_NCLE_DIR_BLOCKS = PATH_NCLE_DIR_DATA / "blocks"
        PATH_NCLE_FILE_CONF = PATH_NCLE_DIR_CONF / "ncle.conf"
        PATH_XTALK_DIR_INBOX = PATH_XTALK_DIR_DATA / "in"
        PATH_XTALK_DIR_OTHER = PATH_XTALK_DIR_DATA / "other"
        PATH_XTALK_DIR_OUTBOX = PATH_XTALK_DIR_DATA / "out"
        PATH_XTALK_DIR_RECEIPTS = PATH_XTALK_DIR_DATA / "receipts"
        PATH_XTALK_FILE_HOSTS = PATH_XTALK_DIR_DATA / "hosts.txt"
        PATH_NCLE_FILE_ID = PATH_NCLE_DIR_DATA / "id"
        PATH_NCLE_FILE_KEY = PATH_NCLE_DIR_DATA / "privkey.pem"
        PATH_NCLE_FILE_PROBES = PATH_NCLE_DIR_DATA / "probes.txt"
else:
        PATH_NCLE_DIR_DATA = Path("/usr/local/var/ncle")
        PATH_NCLE_DIR_COMMON = Path("/usr/local/share/ncle")
        PATH_NCLE_DIR_CONF = Path("/usr/local/etc/ncle")
        PATH_XTALK_DIR_DATA = Path("/usr/local/var/xtalk")
        PATH_XTALK_DIR_COMMON = Path("/usr/local/share/xtalk")
        PATH_XTALK_DIR_CONF = Path("/usr/local/etc/xtalk")

        PATH_NCLE_DIR_BLOCKS = PATH_NCLE_DIR_DATA / "blocks"
        PATH_NCLE_FILE_CONF = PATH_NCLE_DIR_CONF / "ncle.conf"
        PATH_XTALK_DIR_INBOX = PATH_XTALK_DIR_DATA / "in"
        PATH_XTALK_DIR_OTHER = PATH_XTALK_DIR_DATA / "other"
        PATH_XTALK_DIR_OUTBOX = PATH_XTALK_DIR_DATA / "out"
        PATH_XTALK_DIR_RECEIPTS = PATH_XTALK_DIR_DATA / "receipts"
        PATH_XTALK_FILE_HOSTS = PATH_XTALK_DIR_DATA / "hosts"
        PATH_NCLE_FILE_ID = PATH_NCLE_DIR_COMMON / "id"
        PATH_NCLE_FILE_KEY = PATH_NCLE_DIR_CONF / "privkey.pem"
        PATH_NCLE_FILE_PROBES = PATH_NCLE_DIR_DATA / "probes"
##########


class App():
        def __init__(self, connection, address):
                self.address = address
                self.connection = connection

        def __eq__(self, other):
                if isinstance(other, App) and \
                   self.address == other.address:
                        return True
                else:
                        return False


class Host():
        def __init__(self, address, port):
                self.address = address
                self.lastExchangeReceived = None
                self.lastExchangeSent = None
                self.lastProbed = None
                self.lastReachAttempt = None
                self.lastReached = None
                self.port = port
                self.reachable = False

                if isinstance(port, str):
                        self.port = int(port)
                else:
                        self.port = port
        
        def __eq__(self, other):
                if isinstance(other, Host) and \
                   self.address == other.address and \
                   self.port == other.port:
                        return True
                else:
                        return False
        
        def __hash__(self):
                return hash(f"{self.address}:{self.port}")

        def __repr__(self):
                if self.reachable:
                        return f"[1] Host {self.address}:{self.port}"
                else:
                        return f"[0] Host {self.address}:{self.port}"

        def __str__(self):
                if self.reachable:
                        return f"[1] Host {self.address}:{self.port}"
                else:
                        return f"[0] Host {self.address}:{self.port}"


class MessageBlock():
        # MESSAGE BLOCK STRUCTURE
        #########################
        # 1) MAGIC NUMBER
        # ---------------------------------------
        # 2) PROTOCOL VERSION (1 byte)
        # ---------------------------------------
        # 3) BLOCK HASH (8 bytes)
        #----------------------------------------
        # 4) SIGNATURE SIZE (2 bytes)
        #----------------------------------------
        # 5) SIGNATURE (var)
        #----------------------------------------
        # 6) MESSAGE IDENTIFIER (32 bytes)
        #----------------------------------------
        # 7) SENDER TOKEN (32 bytes)
        #----------------------------------------
        # 8) RECIPIENT TOKEN (32 bytes)
        #----------------------------------------
        # 9) TIMESTAMP (8 bytes)
        #----------------------------------------
        # 10) SENDER PUBLIC KEY SIZE (2 bytes)
        #----------------------------------------
        # 11) SENDER PUBLIC KEY (var)
        #----------------------------------------
        # 12) RECIPIENT PUBLIC KEY SIZE (2 bytes)
        #----------------------------------------
        # 13) RECIPIENT PUBLIC KEY (var)
        #----------------------------------------
        # 14) PAYLOAD SIZE (2 bytes)
        #----------------------------------------
        # 15) PAYLOAD (var)
        #----------------------------------------
        #       1) REPLY-TO IDENTIFIER SIZE (1 byte)
        #----------------------------------------------
        #       2) REPLY-TO IDENTIFIER (var)
        #----------------------------------------------
        #       3) SENDER IDENTIFIER SIZE (2 bytes)
        #----------------------------------------------
        #       4) SENDER IDENTIFIER (var)
        #----------------------------------------------
        #       3) SERVICE IDENTIFIER SIZE (2 bytes)
        #----------------------------------------------
        #       4) SERVICE IDENTIFIER (var)
        #----------------------------------------------

        MAGIC_NUM_ENCRYPTED_PAYLOAD = bytearray([0x46, 0x45, 0x50, 0x46])
        MAGIC_NUM = bytearray([0x90, 0x51, 0x45, 0x49, 0x5b, 0x0e, 0x0b, 0x1b, 0x0b])
        PROTOCOL_VER = 0
        
        # recipient must be an instance of MessageRecipient.
        def __init__(self, recipient=None, senderPublicKey=None, payload=None):
                if recipient is not None:
                        self.recipient = recipient
                        # The user part is stored in hashed form.
                        self.recipient.user = hashlib.sha256(recipient.user.encode()).digest()
                else:
                        self.recipient = None

                self.blockHash = None
                self.identifier = hashlib.sha256(uuid.uuid4().bytes).digest()
                self.isEncrypted = False
                self.payload = payload
                self.inReplyTo = None
                self.sender = None
                self.senderRaw = None
                self.senderPublicKey = senderPublicKey
                self.signature = None
                self.timestamp = datetime.now()
                self.version = self.PROTOCOL_VER
        
        def __eq__(self, other):
                if isinstance(other, MessageBlock) and \
                   self.identifier == other.identifier:
                        return True
                else:
                        return False
        
        def __hash__(self):
                return hash(self.identifier)
        
        def __repr__(self):
                return f"<MessageBlock: {self.identifier.hex()}>"

        def __str__(self):
                return f"<MessageBlock: {self.identifier.hex()}>"
        
        def decrypt(self, privateKey, recipientPublicKey):
                if privateKey is None:
                        raise ValueError("MessageBlock.decrypt(2): privateKey is None")
                elif recipientPublicKey is None:
                        raise ValueError("MessageBlock.decrypt(2): recipientPublicKey is None")
                
                if self.payload is None or not MessageBlock.isEncryptedPayload(self.payload):
                        return
                
                # Generate the derived key using Diffie-Hellman.
                sharedKey = privateKey.exchange(ec.ECDH(), recipientPublicKey)
                derivedKey = HKDF(
                        algorithm=hashes.SHA256(),
                        length=32,
                        salt=self.identifier,
                        info=self.identifier,
                        backend=default_backend()
                ).derive(sharedKey)
                # Decrypt.
                iv = self.identifier[:16]
                cipher = Cipher(algorithms.AES(derivedKey), modes.CBC(iv), backend=default_backend())
                decryptor = cipher.decryptor()
                # Make sure to skip the magic number before decryption!
                plaintext = decryptor.update(self.payload[len(self.MAGIC_NUM_ENCRYPTED_PAYLOAD):]) + decryptor.finalize()
                # Check if decryption succeeded. We can tell if the plaintext begins the encryption magic number.
                offset = len(MessageBlock.MAGIC_NUM_ENCRYPTED_PAYLOAD)
                if plaintext[:offset] != MessageBlock.MAGIC_NUM_ENCRYPTED_PAYLOAD:
                        raise Exception("MessageBlock.decrypt(2): invalid magic number - decryption failed!")

                # Decryption succeeded if we reach this point.
                #
                # Original payload size (2 bytes)
                originalPayloadSize = int.from_bytes(
                        plaintext[offset:offset+2], 
                        byteorder="big", 
                        signed=False
                        )
                offset += 2
                # Reply-to identifier size (1 byte)
                replyToIdentifierSize = int.from_bytes(
                        plaintext[offset:offset+1], 
                        byteorder="big", 
                        signed=False
                        )
                offset += 1
                # Reply-to identifier
                if replyToIdentifierSize > 0:
                        inReplyTo = bytes(plaintext[offset:offset + replyToIdentifierSize])
                else:
                        inReplyTo = None
                offset += replyToIdentifierSize
                # Sender identifier size (2 bytes)
                senderIdentifierSize = int.from_bytes(
                        plaintext[offset:offset+2], 
                        byteorder="big", 
                        signed=False
                        )
                offset += 2
                # Sender raw identifier
                sender = bytes(plaintext[offset:offset+senderIdentifierSize]).decode()
                offset += senderIdentifierSize
                # Service identifier size (2 bytes)
                serviceIdentifierSize = int.from_bytes(
                        plaintext[offset:offset+2], 
                        byteorder="big", 
                        signed=False
                        )
                offset += 2
                # Service identifier
                if serviceIdentifierSize > 0:
                        service = bytes(plaintext[offset:offset+serviceIdentifierSize]).decode()
                else:
                        service = None
                offset += serviceIdentifierSize
                # Message part of the payload.
                # The message size is the payload size - the byte that holds the size of the 
                # reply-to identifier, the reply-to identifier itself, the 2 bytes that hold 
                # the size of the sender's identifier, the identifier itself, the 2 bytes that 
                # hold the size of the service identifier, and the service identifier itself.
                payloadMessageSize = originalPayloadSize - replyToIdentifierSize - senderIdentifierSize - serviceIdentifierSize - 5
                payload = plaintext[offset:offset+payloadMessageSize].decode()
                offset += payloadMessageSize
                # We don't set these in the instance variables directly; return them as a tuple.
                return (inReplyTo, sender, service, payload)
        
        @staticmethod
        def deserialise(blockByteArray):
                # 1) Magic number
                if blockByteArray[:len(MessageBlock.MAGIC_NUM)] != MessageBlock.MAGIC_NUM:
                        raise Exception("MessageBlock.deserialise(1): invalid magic number!")

                block = MessageBlock()
                block.recipient = MessageRecipient()
                offset = len(MessageBlock.MAGIC_NUM)
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
                block.signature = bytes(blockByteArray[offset:offset+signatureSize])
                offset += signatureSize
                # 6) Message identifier (32 bytes)
                block.identifier = bytes(blockByteArray[offset:offset+32])
                offset += 32
                # 7) Sender token hash (32 bytes)
                block.sender = bytes(blockByteArray[offset:offset+32])
                offset += 32
                # 8) Recipient token hash (32 bytes)
                block.recipient.user = bytes(blockByteArray[offset:offset+32])
                offset += 32
                # 9) Timestamp (8 bytes)
                time = int.from_bytes(
                        blockByteArray[offset:offset+8], 
                        byteorder="big", 
                        signed=True
                        )
                block.timestamp = datetime.fromtimestamp(time)
                offset += 8
                # 10) Sender Public key size (2 bytes)
                senderPublicKeySize = int.from_bytes(
                        blockByteArray[offset:offset+2], 
                        byteorder="big", 
                        signed=False
                        )
                offset += 2
                # 11) Sender Public key
                block.senderPublicKey = load_der_public_key(bytes(blockByteArray[offset:offset+senderPublicKeySize]), backend=default_backend())
                offset += senderPublicKeySize
                # 12) Recipient Public key size (2 bytes)
                recipientPublicKeySize = int.from_bytes(
                        blockByteArray[offset:offset+2], 
                        byteorder="big", 
                        signed=False
                        )
                offset += 2
                # 13) Recipient Public key
                if recipientPublicKeySize > 0:
                        block.recipient.publicKey = load_der_public_key(bytes(blockByteArray[offset:offset+recipientPublicKeySize]), backend=default_backend())
                        offset += recipientPublicKeySize
                # Check if the keys are valid EC public keys.
                if not isinstance(block.senderPublicKey, ec.EllipticCurvePublicKey):
                        raise TypeError("MessageBlock.deserialise(1): invalid sender EC public key!")
                if block.recipient.publicKey is not None and not isinstance(block.recipient.publicKey, ec.EllipticCurvePublicKey):
                        raise Exception("MessageBlock.deserialise(1): invalid recipient EC public key!")
                
                # 14) Payload size (2 bytes)
                payloadSize = int.from_bytes(
                        blockByteArray[offset:offset+2], 
                        byteorder="big", 
                        signed=False
                        )
                offset += 2
                # Check whether the payload is encrytpted or not.
                block.isEncrypted = MessageBlock.isEncryptedPayload(blockByteArray[offset:offset+payloadSize])
                if block.isEncrypted:
                        # Copy the encrypted payload as-is, excluding the encryption magic number.
                        offset += len(MessageBlock.MAGIC_NUM_ENCRYPTED_PAYLOAD)
                        block.payload = blockByteArray[offset:offset+payloadSize]
                else:
                        # Payload is still raw, meaning we can see the sender and service identifier.
                        # 15) Reply-to identifier size (1 byte)
                        inReplyToIdentifierSize = int.from_bytes(
                                blockByteArray[offset:offset+1], 
                                byteorder="big", 
                                signed=False
                                )
                        offset += 1
                        # 16) Reply-to identifier.
                        if inReplyToIdentifierSize > 0:
                                block.inReplyTo = bytes(blockByteArray[offset:offset + inReplyToIdentifierSize])
                        else:
                                block.inReplyTo = None
                        offset += inReplyToIdentifierSize
                        # 17) Sender identifier size (2 bytes)
                        senderIdentifierSize = int.from_bytes(
                                blockByteArray[offset:offset+2], 
                                byteorder="big", 
                                signed=False
                                )
                        offset += 2
                        # 18) The sender's raw identifier.
                        block.senderRaw = bytes(blockByteArray[offset:offset+senderIdentifierSize]).decode()
                        offset += senderIdentifierSize
                        # 19) Service identifier size (2 bytes)
                        serviceIdentifierSize = int.from_bytes(
                                blockByteArray[offset:offset+2], 
                                byteorder="big", 
                                signed=False
                                )
                        offset += 2
                        if serviceIdentifierSize > 0:
                                block.recipient.service = bytes(blockByteArray[offset:offset+serviceIdentifierSize]).decode()
                        offset += serviceIdentifierSize
                        # 20) Payload
                        payloadMessageSize = payloadSize - senderIdentifierSize - serviceIdentifierSize
                        block.payload = blockByteArray[offset:offset+payloadMessageSize].decode()
                        offset += payloadMessageSize

                # Verify the hash. Remeber that only the first 8 bytes are actually stored.
                if block.isEncrypted:
                        # A block with payload that is not encrypted yet will have no hash stored.
                        blockDigest = block.hash()
                        if blockDigest[:8] != block.blockHash:
                                raise Exception("MessageBlock.deserialise(1): invalid block hash!")

                        # Verify the signature.
                        try:
                                block.senderPublicKey.verify(
                                        block.signature, 
                                        blockDigest, 
                                        ec.ECDSA(utils.Prehashed(hashes.SHA256()))
                                        )
                        except InvalidSignature:
                                raise Exception("MessageBlock.deserialise(1): invalid block signature!")
                
                return block

        def dump(self, location="messages"):
                if location == "messages":
                        blockPoolPath = PATH_XTALK_DIR_OTHER
                elif location == "inbox":
                        blockPoolPath = PATH_XTALK_DIR_INBOX
                else:
                        blockPoolPath = PATH_XTALK_DIR_OUTBOX

                blockByteArray = bytes(self.serialise())
                blockFilePath = os.path.join(blockPoolPath, self.identifier.hex() + "." + FILE_EXT_XTALK)
                
                newFile = open(blockFilePath, "w+b")
                newFile.write(blockByteArray)
        
        def encrypt(self, privateKey, recipientPublicKey):
                if privateKey is None:
                        raise ValueError("MessageBlock.encrypt(2): privateKey is None")
                elif recipientPublicKey is None:
                        raise ValueError("MessageBlock.encrypt(2): recipientPublicKey is None")
                
                # Prepare the payload in a buffer in the xTalk Encrypted Payload format for encryption.
                # 1) Reply-to identifier
                if self.inReplyTo is not None:
                        inReplyToIdentifierSize = len(self.inReplyTo)
                else:
                        inReplyToIdentifierSize = 0
                inReplyToIdentifierSizeBytes = inReplyToIdentifierSize.to_bytes(
                        1, 
                        byteorder="big", 
                        signed=False
                        )
                buffer = bytearray(inReplyToIdentifierSizeBytes)
                if self.inReplyTo is not None:
                        buffer.extend(self.inReplyTo)
                # 2) Sender raw identifier
                senderIdentifierBytes = self.senderRaw.encode()
                senderIdentifierSize = len(senderIdentifierBytes)
                senderIdentifierSizeBytes = senderIdentifierSize.to_bytes(
                        2, 
                        byteorder="big", 
                        signed=False
                        )
                buffer.extend(senderIdentifierSizeBytes)
                buffer.extend(senderIdentifierBytes)
                # 3) Service identifier
                if self.recipient.service is not None:
                        serviceIdentifierBytes = self.recipient.service.encode()
                        serviceIdentifierSize = len(serviceIdentifierBytes)
                else:
                        serviceIdentifierBytes = None
                        serviceIdentifierSize = 0
                
                serviceIdentifierSizeBytes = serviceIdentifierSize.to_bytes(
                        2, 
                        byteorder="big", 
                        signed=False
                        )
                buffer.extend(serviceIdentifierSizeBytes)
                if serviceIdentifierBytes is not None:
                        buffer.extend(serviceIdentifierBytes)
                # The message part of the payload.
                buffer.extend(self.payload.encode())
                # We now need to store the size of the payload BEFORE encryption within the
                # encrypted envelope. The payload size outside reflects its size after any
                # potential padding.
                payloadSize = len(buffer)
                payloadSizeBytes = payloadSize.to_bytes(
                        2, 
                        byteorder="big", 
                        signed=False
                        )
                # Prepend it to the buffer.
                buffer = bytearray(payloadSizeBytes) + buffer

                # Finally, we prepend the encryption magic number. This helps us check after decryption
                # whether decryption actually succeeded or not.
                buffer = bytearray(self.MAGIC_NUM_ENCRYPTED_PAYLOAD) + buffer

                # Encryption uses AES in CBC mode with 128-bit blocks, so we have to make sure
                # the buffer size is a multiple of 16.
                blockSize = 16
                bufferSize = len(buffer)
                if bufferSize < blockSize:
                        padding = os.urandom(blockSize-bufferSize)
                        buffer.extend(padding)
                else:
                        rem = bufferSize % blockSize
                        if rem != 0:
                                nextBlockSize = math.ceil(bufferSize / blockSize) * blockSize
                                blockRemainingSize = nextBlockSize - rem
                                # Add padding.
                                padding = os.urandom(blockRemainingSize)
                                buffer.extend(padding)

                # Generate the derived key using Diffie-Hellman.
                sharedKey = privateKey.exchange(ec.ECDH(), recipientPublicKey)
                derivedKey = HKDF(
                        algorithm=hashes.SHA256(),
                        length=32,
                        salt=self.identifier,
                        info=self.identifier,
                        backend=default_backend()
                ).derive(sharedKey)
                # Encrypt.
                iv = self.identifier[:16]
                cipher = Cipher(algorithms.AES(derivedKey), modes.CBC(iv), backend=default_backend())
                encryptor = cipher.encryptor()
                ciphertext = encryptor.update(bytes(buffer)) + encryptor.finalize()
                # Prepend the encryption magic number and store.
                payload = bytearray(self.MAGIC_NUM_ENCRYPTED_PAYLOAD) + ciphertext
                # We don't set this in the instance variable directly; return it.
                return payload
        
        def hash(self):
                # We pack everything from the block into a buffer
                # excluding the magic number, signature,
                # and the hash itself (obviously).
                #
                # REMINDER: do not hash a block unless it's encrypted.

                # 1) Protocol version
                versionBytes = self.version.to_bytes(
                        1, 
                        byteorder="big", 
                        signed=False
                        )
                buffer = bytearray(versionBytes)
                # 2) Message identifier
                buffer.extend(self.identifier)
                # 3) Sender token hash
                buffer.extend(self.sender)
                # 4) Recipient token hash
                buffer.extend(self.recipient.user)
                # 5) Timestamp
                time = int(self.timestamp.timestamp())
                timeBytes = time.to_bytes(
                        8, 
                        byteorder="big", 
                        signed=True
                        )
                buffer.extend(timeBytes)
                # 6) Sender Public key size
                senderPublicKeyBytes = self.senderPublicKey.public_bytes(
                        encoding=serialization.Encoding.DER,
                        format=serialization.PublicFormat.SubjectPublicKeyInfo
                        )
                senderPublicKeySize = len(senderPublicKeyBytes)
                senderPublicKeySizeBytes = senderPublicKeySize.to_bytes(
                        2, 
                        byteorder="big", 
                        signed=False
                        )
                buffer.extend(senderPublicKeySizeBytes)
                # 7) Sender Public key
                buffer.extend(senderPublicKeyBytes)
                # 8) Recipient Public key size
                if self.recipient.publicKey is not None:
                        recipientPublicKeyBytes = self.recipient.publicKey.public_bytes(
                                encoding=serialization.Encoding.DER,
                                format=serialization.PublicFormat.SubjectPublicKeyInfo
                                )
                        recipientPublicKeySize = len(recipientPublicKeyBytes)
                else:
                        recipientPublicKeyBytes = None
                        recipientPublicKeySize = 0
                
                recipientPublicKeySizeBytes = recipientPublicKeySize.to_bytes(
                        2, 
                        byteorder="big", 
                        signed=False
                        )
                buffer.extend(recipientPublicKeySizeBytes)
                # 9) Recipient Public key
                if recipientPublicKeyBytes is not None:
                        buffer.extend(recipientPublicKeyBytes)
                # 10) Payload size
                if self.isEncrypted:
                        payloadSize = len(self.payload)
                        payloadSizeBytes = payloadSize.to_bytes(
                                2, 
                                byteorder="big", 
                                signed=False
                                )
                        buffer.extend(payloadSizeBytes)
                        # 11) Payload
                        buffer.extend(self.MAGIC_NUM_ENCRYPTED_PAYLOAD)
                        buffer.extend(self.payload)
                else:
                        # 11) Reply-to identifier size
                        if self.inReplyTo is not None:
                                inReplyToIdentifierSize = len(self.inReplyTo)
                        else:
                                inReplyToIdentifierSize = 0
                        inReplyToIdentifierSizeBytes = inReplyToIdentifierSize.to_bytes(
                                1, 
                                byteorder="big", 
                                signed=False
                                )
                        buffer.extend(inReplyToIdentifierSizeBytes)
                        # 12) Reply-to identifier
                        if self.inReplyTo is not None:
                                buffer.extend(self.inReplyTo)
                        # 13) Sender identifier size
                        senderIdentifierBytes = self.senderRaw.encode()
                        senderIdentifierSize = len(senderIdentifierBytes)
                        senderIdentifierSizeBytes = senderIdentifierSize.to_bytes(
                                2, 
                                byteorder="big", 
                                signed=False
                                )
                        buffer.extend(senderIdentifierSizeBytes)
                        # 14) Sender identifier
                        buffer.extend(senderIdentifierBytes)
                        # 15) Service identifier size
                        if self.recipient.service is not None:
                                serviceIdentifierBytes = self.recipient.service.encode()
                                serviceIdentifierSize = len(serviceIdentifierBytes)
                        else:
                                serviceIdentifierBytes = None
                                serviceIdentifierSize = 0
                        
                        serviceIdentifierSizeBytes = serviceIdentifierSize.to_bytes(
                                2, 
                                byteorder="big", 
                                signed=False
                                )
                        buffer.extend(serviceIdentifierSizeBytes)
                        # 16) Service identifier
                        if serviceIdentifierBytes is not None:
                                buffer.extend(serviceIdentifierBytes)
                        # 17) Payload
                        buffer.extend(self.payload.encode())

                return hashlib.sha256(buffer).digest()

        @staticmethod
        def isEncryptedPayload(payload):
                if len(payload) > len(MessageBlock.MAGIC_NUM_ENCRYPTED_PAYLOAD):
                        if payload[:len(MessageBlock.MAGIC_NUM_ENCRYPTED_PAYLOAD)] != MessageBlock.MAGIC_NUM_ENCRYPTED_PAYLOAD:
                                return False
                        else:
                                return True
                else:
                        return False
        
        @staticmethod
        def read(messageIdentifier, location="messages"):
                try:
                        if location == "messages":
                                blockPoolPath = PATH_XTALK_DIR_OTHER
                        elif location == "inbox":
                                blockPoolPath = PATH_XTALK_DIR_INBOX
                        else:
                                blockPoolPath = PATH_XTALK_DIR_OUTBOX

                        blockFilePath = os.path.join(blockPoolPath, messageIdentifier + "." + FILE_EXT_XTALK)
                        with open(blockFilePath, mode="rb") as file:
                                blockByteArray = bytearray(file.read())
                                block = MessageBlock.deserialise(blockByteArray)
                                return block
                except EnvironmentError:
                        return None
        
        def serialise(self):
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
                # 6) Message identifier
                blockByteArray.extend(self.identifier)
                # 7) Sender token hash
                blockByteArray.extend(self.sender)
                # 8) Recipient token hash
                blockByteArray.extend(self.recipient.user)
                # 9) Timestamp
                time = int(self.timestamp.timestamp())
                timeBytes = time.to_bytes(
                        8, 
                        byteorder="big", 
                        signed=True
                        )
                blockByteArray.extend(timeBytes)
                # 10) Sender Public key size
                senderPublicKeyBytes = self.senderPublicKey.public_bytes(
                        encoding=serialization.Encoding.DER,
                        format=serialization.PublicFormat.SubjectPublicKeyInfo
                        )
                senderPublicKeySize = len(senderPublicKeyBytes)
                senderPublicKeySizeBytes = senderPublicKeySize.to_bytes(
                        2, 
                        byteorder="big", 
                        signed=False
                        )
                blockByteArray.extend(senderPublicKeySizeBytes)
                # 11) Sender Public key
                blockByteArray.extend(senderPublicKeyBytes)
                # 12) Recipient Public key size
                if self.recipient.publicKey is not None:
                        recipientPublicKeyBytes = self.recipient.publicKey.public_bytes(
                                encoding=serialization.Encoding.DER,
                                format=serialization.PublicFormat.SubjectPublicKeyInfo
                                )
                        recipientPublicKeySize = len(recipientPublicKeyBytes)
                else:
                        recipientPublicKeyBytes = None
                        recipientPublicKeySize = 0
                
                recipientPublicKeySizeBytes = recipientPublicKeySize.to_bytes(
                        2, 
                        byteorder="big", 
                        signed=False
                        )
                blockByteArray.extend(recipientPublicKeySizeBytes)
                # 13) Recipient Public key
                if recipientPublicKeyBytes is not None:
                        blockByteArray.extend(recipientPublicKeyBytes)
                # 14) Payload size
                if self.isEncrypted:
                        payloadSize = len(self.payload)
                        payloadSizeBytes = payloadSize.to_bytes(
                                2, 
                                byteorder="big", 
                                signed=False
                                )
                        blockByteArray.extend(payloadSizeBytes)
                        # 15) Payload
                        blockByteArray.extend(self.MAGIC_NUM_ENCRYPTED_PAYLOAD)
                        blockByteArray.extend(self.payload)
                else:
                        # 15) Reply-to identifier size
                        if self.inReplyTo is not None:
                                inReplyToIdentifierSize = len(self.inReplyTo)
                        else:
                                inReplyToIdentifierSize = 0
                        inReplyToIdentifierSizeBytes = inReplyToIdentifierSize.to_bytes(
                                1, 
                                byteorder="big", 
                                signed=False
                                )
                        blockByteArray.extend(inReplyToIdentifierSizeBytes)
                        # 16) Reply-to identifier
                        if self.inReplyTo is not None:
                                blockByteArray.extend(self.inReplyTo)
                        # 17) Sender identifier size
                        senderIdentifierBytes = self.senderRaw.encode()
                        senderIdentifierSize = len(senderIdentifierBytes)
                        senderIdentifierSizeBytes = senderIdentifierSize.to_bytes(
                                2, 
                                byteorder="big", 
                                signed=False
                                )
                        blockByteArray.extend(senderIdentifierSizeBytes)
                        # 18) Sender identifier
                        blockByteArray.extend(senderIdentifierBytes)
                        # 19) Service identifier size
                        if self.recipient.service is not None:
                                serviceIdentifierBytes = self.recipient.service.encode()
                                serviceIdentifierSize = len(serviceIdentifierBytes)
                        else:
                                serviceIdentifierBytes = None
                                serviceIdentifierSize = 0
                        
                        serviceIdentifierSizeBytes = serviceIdentifierSize.to_bytes(
                                2, 
                                byteorder="big", 
                                signed=False
                                )
                        blockByteArray.extend(serviceIdentifierSizeBytes)
                        # 20) Service identifier
                        if serviceIdentifierBytes is not None:
                                blockByteArray.extend(serviceIdentifierBytes)
                        # 21) Payload
                        blockByteArray.extend(self.payload.encode())

                return blockByteArray
        
        def sign(self, blockHash, privateKey):
                if privateKey is None:
                        raise ValueError("MessageBlock.sign(2): privateKey is None")
                elif blockHash is None:
                        raise ValueError("MessageBlock.sign(2): blockHash is None")
                
                signature = privateKey.sign(
                                blockHash,
                                ec.ECDSA(utils.Prehashed(hashes.SHA256()))
                        )
                return signature


class MessageReceipt():
        # MESSAGE RECEIPT STRUCTURE
        ###########################
        # 1) MAGIC NUMBER
        # ------------------------------------
        # 2) PROTOCOL VERSION (1 byte)
        # ------------------------------------
        # 3) RECEIPT HASH (8 bytes)
        #-------------------------------------
        # 4) SIGNATURE SIZE (2 bytes)
        #-------------------------------------
        # 5) SIGNATURE
        #-------------------------------------
        # 6) ORIGINAL MESSAGE IDENTIFIER (32 bytes)
        #-------------------------------------
        # 7) TIMESTAMP (8 bytes)

        MAGIC_NUM = bytearray([0x91, 0x52, 0x46, 0x50, 0x5c, 0x0f, 0x0c, 0x1c, 0x0c])

        def __init__(self, originalMessageIdentifier=None):
                self.originalMessageIdentifier = originalMessageIdentifier
                self.receiptHash = None
                self.signature = None
                self.timestamp = datetime.now()
                self.version = MessageBlock.PROTOCOL_VER
        
        def __eq__(self, other):
                if isinstance(other, MessageReceipt) and \
                   self.originalMessageIdentifier == other.originalMessageIdentifier:
                        return True
                else:
                        return False
        
        def __hash__(self):
                return hash(self.originalMessageIdentifier)
        
        def __repr__(self):
                return f"<MessageReceipt: {self.originalMessageIdentifier.hex()}>"

        def __str__(self):
                return f"<MessageReceipt: {self.originalMessageIdentifier.hex()}>"
        
        @staticmethod
        def deserialise(receiptByteArray):
                # 1) Magic number
                if receiptByteArray[:len(MessageReceipt.MAGIC_NUM)] != MessageReceipt.MAGIC_NUM:
                        raise Exception("MessageReceipt.deserialise(1): invalid magic number!")

                receipt = MessageReceipt()
                offset = len(MessageReceipt.MAGIC_NUM)
                # 2) Protocol version (1 byte)
                receipt.version = int.from_bytes(
                        receiptByteArray[offset:offset+1], 
                        byteorder="big", 
                        signed=False
                        )
                offset += 1
                # 3) Receipt hash (8 bytes)
                receipt.receiptHash = bytes(receiptByteArray[offset:offset+8])
                offset += 8
                # 4) Signature size (2 bytes)
                signatureSize = int.from_bytes(
                        receiptByteArray[offset:offset+2], 
                        byteorder="big", 
                        signed=False
                        )
                offset += 2
                # 5) Signature
                receipt.signature = bytes(receiptByteArray[offset:offset+signatureSize])
                offset += signatureSize
                # 6) Original message identifier (32 bytes)
                receipt.originalMessageIdentifier = bytes(receiptByteArray[offset:offset+32])
                offset += 32
                # 7) Timestamp (8 bytes)
                time = int.from_bytes(
                        receiptByteArray[offset:offset+8], 
                        byteorder="big", 
                        signed=True
                        )
                receipt.timestamp = datetime.fromtimestamp(time)
                offset += 8
                
                return receipt
        
        def dump(self):
                receiptByteArray = bytes(self.serialise())
                receiptFilePath = os.path.join(PATH_XTALK_DIR_RECEIPTS, self.originalMessageIdentifier.hex() + "." + FILE_EXT_XTALK_RECEIPT)
                
                newFile = open(receiptFilePath, "w+b")
                newFile.write(receiptByteArray)
        
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
                # 2) Original message identifier
                buffer.extend(self.originalMessageIdentifier)
                # 3) Timestamp
                time = int(self.timestamp.timestamp())
                timeBytes = time.to_bytes(
                        8, 
                        byteorder="big", 
                        signed=True
                        )
                buffer.extend(timeBytes)

                return hashlib.sha256(buffer).digest()
        
        def isValid(self, originalMessage):
                # Verify the signature.
                try:
                        receiptDigest = self.hash()
                        originalMessage.recipient.publicKey.verify(
                                self.signature, 
                                receiptDigest, 
                                ec.ECDSA(utils.Prehashed(hashes.SHA256()))
                                )
                        
                        return True
                except InvalidSignature:
                        return False
        
        @staticmethod
        def read(originalMessageIdentifier):
                try:
                        receiptFilePath = os.path.join(PATH_XTALK_DIR_RECEIPTS, originalMessageIdentifier + "." + FILE_EXT_XTALK_RECEIPT)
                        with open(receiptFilePath, mode="rb") as file:
                                receiptByteArray = bytearray(file.read())
                                receipt = MessageReceipt.deserialise(receiptByteArray)
                                return receipt
                except EnvironmentError:
                        return None
        
        def serialise(self):
                # 1) Magic number
                receiptByteArray = bytearray(self.MAGIC_NUM)
                # 2) Protocol version
                versionBytes = self.version.to_bytes(
                        1, 
                        byteorder="big", 
                        signed=False
                        )
                receiptByteArray.extend(versionBytes)
                # 3) Receipt hash (first 8 bytes only)
                if self.receiptHash is not None:
                        receiptByteArray.extend(self.receiptHash[:8])
                else:
                        receiptByteArray.extend([0] * 8)
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
                receiptByteArray.extend(signatureSizeBytes)
                # 5) Signature
                if signatureBytes is not None:
                        receiptByteArray.extend(signatureBytes)
                # 6) Original message identifier
                receiptByteArray.extend(self.originalMessageIdentifier)
                # 7) Timestamp
                time = int(self.timestamp.timestamp())
                timeBytes = time.to_bytes(
                        8, 
                        byteorder="big", 
                        signed=True
                        )
                receiptByteArray.extend(timeBytes)

                return receiptByteArray
        
        def sign(self, blockHash, privateKey):
                if privateKey is None:
                        raise ValueError("MessageReceipt.sign(2): privateKey is None")
                elif blockHash is None:
                        raise ValueError("MessageReceipt.sign(2): blockHash is None")
                
                signature = privateKey.sign(
                                blockHash,
                                ec.ECDSA(utils.Prehashed(hashes.SHA256()))
                        )
                return signature


class MessageRecipient():
        def __init__(self, publicKey=None, service=None, user=None):
                self.publicKey = publicKey
                self.userIsBlob = False

                if service is not None and len(service) > 0:
                        self.service = service
                else:
                        self.service = None
                
                if user is not None and len(user) > 0:
                        self.user = user
                else:
                        self.user = None
        
        def __eq__(self, other):
                if isinstance(other, MessageRecipient) and \
                   self.service == other.service and \
                   self.user == other.user:
                        return True
                else:
                        return False
        
        def __hash__(self):
                if isinstance(self.user, bytes) or isinstance(self.user, bytearray):
                        if self.userIsBlob:
                                user = hashlib.sha256(self.user).hexdigest()
                        else:
                                user = self.user.hex()
                else:
                        user = user

                if self.service is not None and self.user is not None:
                        return hash(f"{self.service}@{user}")
                elif self.user is not None:
                        return hash(f"@{user}")
                else:
                        return hash(f"{self.service}")

        def __repr__(self):
                if isinstance(self.user, bytes) or isinstance(self.user, bytearray):
                        if self.userIsBlob:
                                user = hashlib.sha256(self.user).hexdigest()
                        else:
                                user = self.user.hex()
                else:
                        user = user
                
                if self.service is not None and self.user is not None:
                        return f"{self.service}@{user}"
                elif self.user is not None:
                        return f"@{user}"
                else:
                        return f"{self.service}"

        def __str__(self):
                if isinstance(self.user, bytes) or isinstance(self.user, bytearray):
                        if self.userIsBlob:
                                user = hashlib.sha256(self.user).hexdigest()
                        else:
                                user = self.user.hex()
                else:
                        user = user
                
                if self.service is not None and self.user is not None:
                        return f"{self.service}@{user}"
                elif self.user is not None:
                        return f"@{user}"
                else:
                        return f"{self.service}"


class ProtocolMessage():
        # PROTOCOL MESSAGE STRUCTURE
        ############################
        # 1) VERSION (1 byte)
        # ------------------------------------
        # 2) TYPE (1 byte)
        #-------------------------------------
        # 3) ERROR CODE (1 byte)
        #-------------------------------------
        # 4) BODY SIZE (8 bytes)
        #-------------------------------------
        # 5) BODY

        currentProtocolVersion = 0

        def __init__(self, data=None):
                if data is not None:
                        self.version = int.from_bytes(
                                data[:1], 
                                byteorder="big", 
                                signed=False
                                )
                        self.type = int.from_bytes(
                                data[1:2], 
                                byteorder="big", 
                                signed=False
                                )
                        self.errorCode = int.from_bytes(
                                data[2:3], 
                                byteorder="big", 
                                signed=False
                                )

                        bodySize = int.from_bytes(
                                data[3:11], 
                                byteorder="big", 
                                signed=False
                                )
                        if bodySize > 0:
                                self.body = bytes(data[11:11+bodySize])
                        else:
                                self.body = None
                else:
                        self.version = self.currentProtocolVersion
                        self.type = ProtocolMessageType.UNDEFINED
                        self.errorCode = 0
                        self.body = None

        def serialise(self):
                messageByteArray = bytearray()

                versionBytes = self.version.to_bytes(
                        1, 
                        byteorder="big", 
                        signed=False
                        )
                messageByteArray.extend(versionBytes)
                
                typeBytes = self.type.to_bytes(
                        1, 
                        byteorder="big", 
                        signed=False
                        )
                messageByteArray.extend(typeBytes)
                
                errorCodeBytes = self.errorCode.to_bytes(
                        1, 
                        byteorder="big", 
                        signed=False
                        )
                messageByteArray.extend(errorCodeBytes)

                # NOTE: body must be bytes!
                if self.body is not None:
                        bodySize = len(self.body)
                else:
                        bodySize = 0
                bodySizeBytes = bodySize.to_bytes(
                        8, 
                        byteorder="big", 
                        signed=False
                        )
                messageByteArray.extend(bodySizeBytes)

                if self.body is not None:
                        messageByteArray.extend(self.body)

                return messageByteArray
                

class MessageStatus(IntEnum):
        UNDEFINED = 0
        PENDING = auto()
        SENT = auto()
        DELIVERED = auto()


class ProtocolAppKey(str, Enum):
        LOCAL_IDENTIFIER = "me"
        MESSAGE_IDENTIFIER = "ref"
        MESSAGE_STATUS = "status"
        PAYLOAD = "body"
        RECIPIENT = "to"
        RECIPIENT_ID_FILE = "id"        # • For future development.
        REPLY_TO = "re"
        SENDER = "from"
        SERVICES = "interest"
        TIMESTAMP = "time"
        WHO_AM_I = "address"
        WILDCARD_SERVICE = "*"


class ProtocolMessageType(IntEnum):
        UNDEFINED = 0
        HOST = auto()                   # • The IP address and port of a messenger instance.
        MESSAGE = auto()                # • For sending a message block.
        PING = auto()                   # • Sent to check if a host is reachable.
        PONG = auto()                   # • Sent in response to a ping.
        RECEIPT = auto()                # • Sent if a message has already been delivered.
        WHO_AM_I = auto()               # • Sent to neighbours to unmask the local machine's public IP address.
        YOU_ARE = auto()                # • Sent in response to WHO_AM_I containing their apparent IP address.
        

class Messenger():
        ADDRESS_DISCOVERY_NEIGHBOURS = 5        # Query this many neighbours during public IP address discovery
        AGE_HOST = timedelta(days=15)           # Days after which an unreachable host gets purged
        AGE_RECEIPT = timedelta(days=15)        # Days after which a receipt gets purged
        DEFAULT_HOSTS = {"35.176.210.85:1993"}
        FIELD_DELIMITER = "\r\n"
        INTERVAL_ADDRESS_DISCOVERY = 60 * 15    # 15 minutes
        INTERVAL_HOST_PING = 20                 # Seconds
        INTERVAL_POOL_EXCHANGE = 60 * 10        # 10 minutes
        INTERVAL_POLL_INBOX = 1                 # Seconds
        INTERVAL_POLL_OUTBOX = 60               # 1 minute normally but make 5 seconds for demo
        INTERVAL_RECEIPT_PURGE = 60 * 60        # 1 hour
        MESSAGE_PAYLOAD_LIMIT = 140             # bytes
        POOL_BLOCK_EXCHANGE_SIZE = 50
        POOL_HOST_EXCHANGE_SIZE = 100
        PORT_MESSENGER = 1993
        
        def __init__(self, portApps=PORT_MESSENGER, portMessengers=PORT_MESSENGER):
                self.apps = {ProtocolAppKey.WILDCARD_SERVICE.value: []}
                self.blockPath = PATH_NCLE_DIR_BLOCKS
                self.hosts = set()
                self.idPath = PATH_NCLE_FILE_ID
                self.isBlobMode = False                 # This means the program reads the identity file in binary mode (i.e. the file could contain anything).
                self.inbox = set()
                self.outbox = set()
                self.portApps = portApps
                self.portMessengers = portMessengers
                self.privateKey = None
                self.privateKeyPath = PATH_NCLE_FILE_KEY
                self.publicAddress = None
                self.userIdentifier = None
                self.userRawIdentifier = None
                self.whoAmIResponses = []
                # SOCKET SETUP
                # Apps talk to the server using a textual protocol over TCP.
                serverAppAddress = ("127.0.0.1", self.portApps)
                self.sockApps = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.sockApps.setsockopt(
                        socket.SOL_SOCKET, 
                        socket.SO_KEEPALIVE, 
                        1
                        )
                self.sockApps.setsockopt(
                        socket.SOL_SOCKET, 
                        socket.SO_REUSEADDR, 
                        1
                        )
                self.sockApps.setsockopt(
                        socket.IPPROTO_TCP, 
                        socket.TCP_NODELAY, 
                        1
                        )
                self.sockApps.bind(serverAppAddress)
                # Other messengers talk to it using a binary protocol over UDP.
                serverMessengerAddress = ("0.0.0.0", self.portMessengers)
                self.sockMessengers = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                self.sockMessengers.setsockopt(
                        socket.SOL_SOCKET, 
                        socket.SO_REUSEADDR, 
                        1
                        )
                self.sockMessengers.bind(serverMessengerAddress)

        def addToOutbox(self, block):
                if block is None:
                        raise ValueError("Messenger.addToOutbox(1): block is None")
                
                self.outbox.add(block)
        
        def blockPool(self):
                # Return a random batch of message blocks.
                files = [filename for filename in os.listdir(PATH_XTALK_DIR_OTHER) if os.path.isfile(os.path.join(PATH_XTALK_DIR_OTHER, filename)) and filename[0] != "."]
                batch = random.sample(files, min(self.POOL_BLOCK_EXCHANGE_SIZE, len(files)))
                pool = []
                for blockFilePath in batch:
                        block = self.readBlock(blockFilePath)
                        pool.append(block)
                return pool
        
        def bootstrap(self):
                # Integrity checks.
                self.checkDirs()
                # Start with the config file to determine where some things ought to go.
                self.readNCLEConfig()

                self.checkHostsFile()
                self.checkInboxDirectory()
                self.checkMessagePool()
                self.checkOutboxDirectory()
                self.checkReceiptPool()
                # Load the in/outboxes.
                self.readInbox()
                self.readOutbox()
                # Load the host list.
                self.readHosts()

        def broadcast(self, message, excluding=None):
                for host in self.hosts:
                        if excluding is None or (excluding is not None and host not in excluding):
                                self.sendServerMessage(host, message)

        def checkDirs(self):
                if not os.path.exists(PATH_XTALK_DIR_DATA):
                        PATH_XTALK_DIR_DATA.mkdir(parents=True)

        def checkHostsFile(self):
                if not os.path.exists(PATH_XTALK_FILE_HOSTS):
                        fileContents = "\n".join(self.DEFAULT_HOSTS)
                        newFile = open(PATH_XTALK_FILE_HOSTS, "w+")
                        newFile.write(fileContents)

        def checkInboxDirectory(self):
                if not os.path.exists(PATH_XTALK_DIR_INBOX):
                        path = PATH_XTALK_DIR_INBOX
                        path.mkdir(parents=True)

        def checkMessagePool(self):
                if not os.path.exists(PATH_XTALK_DIR_OTHER):
                        path = PATH_XTALK_DIR_OTHER
                        path.mkdir(parents=True)

        def checkOutboxDirectory(self):
                if not os.path.exists(PATH_XTALK_DIR_OUTBOX):
                        path = PATH_XTALK_DIR_OUTBOX
                        path.mkdir(parents=True)

        def checkReceiptPool(self):
                if not os.path.exists(PATH_XTALK_DIR_RECEIPTS):
                        path = PATH_XTALK_DIR_RECEIPTS
                        path.mkdir(parents=True)
        
        def deleteFromInbox(self, block):
                if block is None:
                        raise ValueError("Messenger.deleteFromInbox(1): block is None")
                elif not isinstance(block, MessageBlock):
                        raise TypeError("Messenger.deleteFromInbox(1): block is not an instance of MessageBlock")

                self.inbox.discard(block)

        def deleteFromInboxDirectory(self, messageIdentifier):
                if messageIdentifier is None:
                        raise ValueError("Messenger.deleteFromInboxDirectory(1): messageIdentifier is None")
                elif not isinstance(messageIdentifier, str):
                        raise TypeError("Messenger.deleteFromInboxDirectory(1): messageIdentifier is not a string")

                blockFilePath = os.path.join(PATH_XTALK_DIR_INBOX, messageIdentifier + "." + FILE_EXT_XTALK)
                if os.path.exists(blockFilePath):
                        os.remove(blockFilePath)
        
        def deleteFromMessagesDirectory(self, messageIdentifier):
                if messageIdentifier is None:
                        raise ValueError("Messenger.deleteFromMessagesDirectory(1): messageIdentifier is None")
                elif not isinstance(messageIdentifier, str):
                        raise TypeError("Messenger.deleteFromMessagesDirectory(1): messageIdentifier is not a string")

                blockFilePath = os.path.join(PATH_XTALK_DIR_OTHER, messageIdentifier + "." + FILE_EXT_XTALK)
                if os.path.exists(blockFilePath):
                        os.remove(blockFilePath)
        
        def deleteFromOutbox(self, block):
                if block is None:
                        raise ValueError("Messenger.deleteFromOutbox(1): block is None")
                elif not isinstance(block, MessageBlock):
                        raise TypeError("Messenger.deleteFromOutbox(1): block is not an instance of MessageBlock")

                self.outbox.discard(block)

        def deleteFromOutboxDirectory(self, messageIdentifier):
                if messageIdentifier is None:
                        raise ValueError("Messenger.deleteFromOutboxDirectory(1): messageIdentifier is None")
                elif not isinstance(messageIdentifier, str):
                        raise TypeError("Messenger.deleteFromOutboxDirectory(1): messageIdentifier is not a string")

                blockFilePath = os.path.join(PATH_XTALK_DIR_OUTBOX, messageIdentifier + "." + FILE_EXT_XTALK)
                if os.path.exists(blockFilePath):
                        os.remove(blockFilePath)

        def deleteFromReceiptsDirectory(self, messageIdentifier):
                if messageIdentifier is None:
                        raise ValueError("Messenger.deleteFromReceiptsDirectory(1): messageIdentifier is None")
                elif not isinstance(messageIdentifier, str):
                        raise TypeError("Messenger.deleteFromReceiptsDirectory(1): messageIdentifier is not a string")
                
                receiptFilePath = os.path.join(PATH_XTALK_DIR_RECEIPTS, messageIdentifier + "." + FILE_EXT_XTALK_RECEIPT)
                if os.path.exists(receiptFilePath):
                        os.remove(receiptFilePath)
        
        def discoverPublicAddress(self):
                while 1:
                        self.whoAmIResponses.clear()

                        neighbours = self.reachableHosts()
                        sample = random.sample(neighbours, min(self.ADDRESS_DISCOVERY_NEIGHBOURS, len(neighbours)))
                        for neighbour in sample:
                                message = ProtocolMessage()
                                message.type = ProtocolMessageType.WHO_AM_I
                                self.sendServerMessage(neighbour, message)
                        
                        time.sleep(self.INTERVAL_ADDRESS_DISCOVERY)
        
        def dumpHosts(self):
                fileContents = ""
                for host in self.hosts:
                        line = f"{host.address}:{host.port}"
                        if host.lastReached is not None:
                                line += f" {int(host.lastReached.timestamp())}"
                        if host.lastReachAttempt is not None:
                                line += f" {int(host.lastReachAttempt.timestamp())}"
                        line += "\n"
                        fileContents += line
                
                hostsFile = open(PATH_XTALK_FILE_HOSTS, "w+")
                hostsFile.write(fileContents)
        
        def exchangeBlockPool(self, host):
                if not host.reachable:
                        return

                # Pools are exchanged at intervals.
                now = datetime.now()
                pool = []
                if host.lastExchangeSent is None or \
                   now - timedelta(seconds=self.INTERVAL_POOL_EXCHANGE) > host.lastExchangeSent <= now:
                        # Put together a batch.
                        pool.extend(self.blockPool())
                        # Update the last-exchange timestamp for this host.
                        host.lastExchangeSent = datetime.now()
                
                # Send them off.
                for block in pool:
                        message = ProtocolMessage()
                        message.type = ProtocolMessageType.MESSAGE
                        message.body = block
                        self.sendServerMessage(host, message)
        
        def exchangeHostPool(self, host):
                if not host.reachable:
                        return
                
                batch = random.sample(self.hosts, min(self.POOL_HOST_EXCHANGE_SIZE, len(self.hosts)))
                for server in batch:
                        # Don't send a dead host.
                        #
                        # NOTE: server.lastReachAttempt is always >= server.lastReached
                        # because it is updated whenever a message is received from the
                        # host as well as when a message is sent to it.
                        if server.lastReachAttempt - server.lastReached <= self.AGE_HOST:
                                messageBody = f"{server.address}:{server.port}"
                                if server.lastReached is not None:
                                        messageBody += f" {int(server.lastReached.timestamp())}"
                                if server.lastReachAttempt is not None:
                                        messageBody += f" {int(server.lastReachAttempt.timestamp())}"

                                message = ProtocolMessage()
                                message.type = ProtocolMessageType.HOST
                                message.body = messageBody.encode()
                                self.sendServerMessage(host, message)
        
        def generateReceipt(self, message):
                if message is None:
                        raise ValueError("Messenger.generateReceipt(1): message is None")
                elif not isinstance(message, MessageBlock):
                        raise TypeError("Messenger.generateReceipt(1): message is not an instance of MessageBlock")

                receipt = MessageReceipt(originalMessageIdentifier=message.identifier)
                receiptDigest = receipt.hash()
                receipt.receiptHash = receiptDigest[:8]
                receipt.signature = receipt.sign(receiptDigest, self.privateKey)

                return receipt

        def handleAppConnection(self, app):
                try:
                        # We still don't know what services this app is interested in.
                        # Wait for a message.
                        while 1:
                                linesRead = self.readAppMessage(app.connection)
                                messageDict = self.parseMessageLines(linesRead)
                                messageBlock = self.makeMessageBlock(messageDict)
        
                                # Return Values:
                                # --
                                # • 0: no error
                                # • -1: an error occurred (badly formed message)
                                if ProtocolAppKey.SERVICES in messageDict:
                                        interestList = messageDict[ProtocolAppKey.SERVICES]
                                        if interestList is not None:
                                                self.registerAppInterests(app, messageDict[ProtocolAppKey.SERVICES])
                                                app.connection.sendall(f"{ProtocolAppKey.SERVICES}: 0".encode())
                                        else:
                                                # Malformed message.
                                                app.connection.sendall(f"{ProtocolAppKey.SERVICES}: -1".encode())
                                elif ProtocolAppKey.LOCAL_IDENTIFIER in messageDict:
                                        if self.userRawIdentifier is not None:
                                                app.connection.sendall(f"{ProtocolAppKey.LOCAL_IDENTIFIER}: {self.userRawIdentifier}".encode())
                                        else:
                                                # No local identity exists.
                                                app.connection.sendall(f"0".encode())
                                elif ProtocolAppKey.MESSAGE_STATUS in messageDict:
                                        messageIdentifier = messageDict[ProtocolAppKey.MESSAGE_STATUS]
                                        if messageIdentifier is not None:
                                                status = self.messageStatus(messageIdentifier)
                                                timestamp = None
                                                # Include time information if possible.
                                                if status == MessageStatus.PENDING:
                                                        message = MessageBlock.read(messageIdentifier, location="outbox")
                                                        timestamp = message.timestamp
                                                elif status == MessageStatus.SENT:
                                                        message = MessageBlock.read(messageIdentifier)
                                                        timestamp = message.timestamp
                                                elif status == MessageStatus.DELIVERED:
                                                        receipt = MessageReceipt.read(messageIdentifier)
                                                        if receipt is not None:
                                                                timestamp = receipt.timestamp
                                                        else:
                                                                message = MessageBlock.read(messageIdentifier, location="inbox")
                                                                if message is not None:
                                                                        timestamp = message.timestamp
                                                
                                                if timestamp is not None:
                                                        app.connection.sendall(f"{ProtocolAppKey.MESSAGE_STATUS}: {status} {timestamp}".encode())
                                                else:
                                                        app.connection.sendall(f"{ProtocolAppKey.MESSAGE_STATUS}: {status}".encode())
                                        else:
                                                # Malformed message.
                                                app.connection.sendall(f"{ProtocolAppKey.MESSAGE_STATUS}: -1".encode())
                                elif ProtocolAppKey.WHO_AM_I in messageDict:
                                        addresses = f"{ProtocolAppKey.WHO_AM_I}: {self.localAddress()}"
                                        if self.publicAddress is not None:
                                                addresses += f",{self.publicAddress}"
                                        app.connection.sendall(addresses.encode())
                                else:
                                        if messageBlock is not None:
                                                # Respond with the fresh message's identifier.
                                                app.connection.sendall(f"{ProtocolAppKey.MESSAGE_IDENTIFIER}: {messageBlock.identifier.hex()}".encode())
                                                print("NEW MESSAGE ADDRESSED TO:", messageBlock.recipient)
                                                print("PAYLOAD:\n", messageBlock.payload)
                                                self.handleOutboundMessage(messageBlock)
                                        else:
                                                # Malformed message.
                                                app.connection.sendall(f"{ProtocolAppKey.SERVICES}: -1".encode())

                                app.connection.sendall(f"{self.FIELD_DELIMITER}".encode())
                                app.connection.sendall(f"{self.FIELD_DELIMITER}".encode())
                except Exception as e:
                        print("Messenger.handleAppConnection():", e)
                finally:
                        print(f"--[APP {app.address} DISCONNECTED]--")
                        for service in list(self.apps):
                                appList = [a for a in self.apps[service] if a != app]
                                # If the list is now empty, delete it.
                                # The wildcard list never gets deleted.
                                if service != ProtocolAppKey.WILDCARD_SERVICE and len(appList) == 0:
                                        self.apps.pop(service)
                                else:
                                        self.apps[service] = appList
                        
                        app.connection.close()
        
        def handleInboundMessage(self, block):
                if block is None:
                        raise ValueError("Messenger.handleInboundMessage(1): block is None")
                elif not isinstance(block, MessageBlock):
                        raise TypeError("Messenger.handleInboundMessage(1): block is not an instance of MessageBlock")

                delivered = False

                if block.isEncrypted:
                        try:
                                # Decrypt to get the service and payload.
                                inReplyTo, sender, service, payload = block.decrypt(self.privateKey, block.senderPublicKey)
                                block.inReplyTo = inReplyTo
                                block.isEncrypted = False
                                block.payload = payload
                                block.recipient.service = service
                                block.senderRaw = sender
                                # Make sure the sender's raw identifier matches the one outside the encrypted payload.
                                if hashlib.sha256(sender.encode()).digest() != block.sender:
                                        raise Exception("Messenger.handleInboundMessage(1): sender's identitifer is spoofed!")
                        except:
                                # If decryption fails, that means this message is encrypted
                                # with someone else's stronger identity key, so we remove it from
                                # the inbox.
                                print("--[DECRYPTION OF MESSAGE PAYLOAD FAILED - DISCARDING BLOCK…]--")
                                self.deleteFromInboxDirectory(block.identifier.hex())
                                self.deleteFromInbox(block)
                                # Place it in the main message pool instead.
                                block.dump()

                                return delivered
                
                if block.recipient.service is not None:
                        if block.recipient.service in self.apps:
                                appList = self.apps[block.recipient.service]
                                if len(appList) > 0:
                                        delivered = True
                                for app in appList:
                                        self.sendAppMessage(app, block)
                else:
                        appList = self.apps[ProtocolAppKey.WILDCARD_SERVICE]
                        if len(appList) > 0:
                                delivered = True
                        for app in appList:
                                self.sendAppMessage(app, block)
                # If the messenger manages to deliver the message to one or more
                # apps, then the message is considered "delivered" and copies can
                # be purged.
                if delivered:
                        self.deleteFromInboxDirectory(block.identifier.hex())
                        self.deleteFromInbox(block)

                        receipt = self.generateReceipt(block)
                        receipt.dump()
                        self.seedReceipt(receipt)

                return delivered
        
        def handleOutboundMessage(self, block):
                if block is None:
                        raise ValueError("Messenger.handleOutboundMessage(1): block is None")
                elif not isinstance(block, MessageBlock):
                        raise TypeError("Messenger.handleOutboundMessage(1): block is not an instance of MessageBlock")

                sent = False
                # Check if the identity block of the recipient exists on the filesystem.
                user = block.recipient.user.hex()
                try:
                        recipientBlock = IdentityBlock.read(self.blockPath / (user + "." + FILE_EXT_NCLE))
                        if recipientBlock is None:
                                print("RECIPIENT NOT FOUND! ADDING TO PROBES FILE…")
                                block.dump(location="outbox")
                                self.probe(user)
                                self.addToOutbox(block)
                        else:
                                print("RECIPIENT EXISTS!")
                                block.recipient.publicKey = recipientBlock.publicKey
                                block.payload = block.encrypt(self.privateKey, recipientBlock.publicKey)
                                block.isEncrypted = True
                                blockDigest = block.hash()
                                block.blockHash = blockDigest[:8]
                                block.signature = block.sign(blockDigest, self.privateKey)

                                self.deleteFromOutboxDirectory(block.identifier.hex())
                                self.deleteFromOutbox(block)
                                # Check if this message was intended for the local user.
                                if self.messageIsAddressedToLocal(block):
                                        print("ADDRESSED TO LOCAL USER!")
                                        self.inbox.add(block)
                                        block.dump(location="inbox")
                                else:
                                        block.dump()
                                        self.seedBlock(block)
                                sent = True
                except Exception as e:
                        print("Messenger.handleOutboundMessage(1):", e)

                return sent

        def handleReceipt(self, receipt):
                if receipt is None:
                        raise ValueError("Messenger.handleReceipt(1): receipt is None")
                elif not isinstance(receipt, MessageReceipt):
                        raise TypeError("Messenger.handleReceipt(1): receipt is not an instance of MessageReceipt")
                
                # Check the timestamp. A receipt set more than 2 hours into the future 
                # or 15 days into the past is rejected.
                now = datetime.now()
                if receipt.timestamp > now + timedelta(hours=2) or \
                   receipt.timestamp < now - timedelta(days=15):
                        print("RECEIPT TIMESTAMP IS BAD!")
                        return

                # Don't do anything if we already have a copy of this receipt.
                existingReceipt = self.readReceipt(receipt.originalMessageIdentifier.hex())
                if existingReceipt is not None:
                        return

                originalMessage = MessageBlock.read(receipt.originalMessageIdentifier.hex())
                if originalMessage is None:
                        return
                
                if receipt.isValid(originalMessage):
                        self.deleteFromMessagesDirectory(originalMessage.identifier.hex())
                        receipt.dump()
        
        def listenForApps(self):
                self.sockApps.listen(1)
                while 1:
                        print("--[WAITING FOR APP CONNECTION…]--")
                        connection, clientAddress = self.sockApps.accept()
                        app = App(connection, clientAddress)

                        print(f"--[APP CONNECTION FROM {clientAddress}]--")

                        appThread = threading.Thread(target=self.handleAppConnection, args=(app,))
                        appThread.daemon = True
                        appThread.start()

        def listenForMessengers(self):
                while 1:
                        # NOTE:
                        # -----
                        # This probably needs to be modified to recv messages of arbitrary sizes.
                        message, address = self.sockMessengers.recvfrom(1024)
                        # Ignore our own LAN broadcast messages.
                        if address[0] != self.localAddress():
                                now = datetime.now()
                                host = Host(address[0], address[1])
                                host.lastReached = now
                                host.lastReachAttempt = now
                                host.reachable = True

                                self.routeMessage(message, host)

        def loadPrivateKey(self):
                if  os.path.exists(self.privateKeyPath):
                        keyFile = open(self.privateKeyPath, "rb")
                        loadedPrivateKey = serialization.load_pem_private_key(
                                keyFile.read(),
                                password=None,
                                backend=default_backend()
                        )
                        return loadedPrivateKey
                else:
                        return None
        
        def localAddress(self):
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                try:
                        # Doesn't even have to be reachable.
                        sock.connect(("10.255.255.255", 1))
                        address = sock.getsockname()[0]
                except Exception:
                        address = "127.0.0.1"
                finally:
                        sock.close()
                return address
        
        def localBroadcast(self):
                message = ProtocolMessage()
                message.type = ProtocolMessageType.PING
                self.sockMessengers.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
                try:
                        self.sockMessengers.sendto(message.serialise(), ("255.255.255.255", self.PORT_MESSENGER))
                except Exception as e:
                        print(e)
                # Turn off the broadcast flag.
                self.sockMessengers.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 0)
        
        def makeMessageBlock(self, messageDict):
                if ProtocolAppKey.RECIPIENT in messageDict and ProtocolAppKey.PAYLOAD not in messageDict:
                        print("COULD NOT CREATE MESSAGE - MISSING PAYLOAD!")
                        return None
                
                if self.userIdentifier is None or self.userRawIdentifier is None:
                        print("COULD NOT CREATE MESSAGE - NO LOCAL IDENTITY FOUND!")
                        return None
                
                if self.privateKey is None:
                        print("COULD NOT CREATE MESSAGE - NO PRIVATE KEY FOUND!")
                        return None

                if ProtocolAppKey.RECIPIENT in messageDict:
                        recipientLine = messageDict[ProtocolAppKey.RECIPIENT]
                        recipient = self.parseRecipient(recipientLine)
                        if ProtocolAppKey.RECIPIENT_ID_FILE in messageDict:
                                with open(messageDict[ProtocolAppKey.RECIPIENT_ID_FILE], "rb") as file:
                                        identifier = file.read()
                                        recipient.user = identifier
                                        recipient.userIsBlob = True
                        elif recipient.user is None:
                                # If no user is specified, fill in with the local user's identity token.
                                recipient.user = self.userRawIdentifier
                else:
                        # No recipient specified, this means it's a generic message to the local user.
                        recipient = MessageRecipient(user=self.userRawIdentifier)

                if ProtocolAppKey.REPLY_TO in messageDict:
                        try:
                                # The reply-to identifier must be a hash, not just any arbitrary string.
                                inReplyTo = unhexlify(messageDict[ProtocolAppKey.REPLY_TO])
                        except Exception:
                                inReplyTo = None
                                pass
                else:
                        inReplyTo = None
                
                if ProtocolAppKey.PAYLOAD in messageDict:
                        payload = messageDict[ProtocolAppKey.PAYLOAD]
                        # Truncate the payload to the limit set by the protocol.
                        payload = payload[:self.MESSAGE_PAYLOAD_LIMIT]
                else:
                        payload = None
                
                block = MessageBlock(recipient=recipient, senderPublicKey=self.privateKey.public_key())
                block.inReplyTo = inReplyTo
                block.payload = payload
                block.sender = self.userIdentifier
                block.senderRaw = self.userRawIdentifier

                return block
        
        def messageStatus(self, messageIdentifier):
                if messageIdentifier is None:
                        raise ValueError("Messenger.messageStatus(1): messageIdentifier is None")
                elif not isinstance(messageIdentifier, str):
                        raise TypeError("Messenger.messageStatus(1): messageIdentifier is not a string")

                if MessageReceipt.read(messageIdentifier) is not None or \
                   MessageBlock.read(messageIdentifier, location="inbox") is not None:
                        return MessageStatus.DELIVERED
                elif MessageBlock.read(messageIdentifier, location="messages") is not None:
                        return MessageStatus.SENT
                elif MessageBlock.read(messageIdentifier, location="outbox") is not None:
                        return MessageStatus.PENDING
                else:
                        return MessageStatus.UNDEFINED
        
        def messageIsAddressedToLocal(self, message):
                if message.recipient.user == self.userIdentifier:
                        return True
                else:
                        return False
        
        def parseHosts(self, hostLines):
                for hostLine in hostLines:
                        lineParts = hostLine.strip().split(" ")
                        if len(lineParts) > 0:
                                # Each line can contain an IP address, a port (concatenated by a colon), 
                                # and a space followed by the last time that the host was reachable.
                                host = None
                                hostAddress = lineParts[0]
                                addressParts = hostAddress.split(":")
                                now = datetime.now()

                                if len(addressParts) == 2:
                                        address = addressParts[0]
                                        port = int(addressParts[1])
                                        # Check if one of the default hosts is the current machine
                                        # in which case don't add it to the set.
                                        if address != self.localAddress():
                                                host = Host(address, port)

                                if host is not None:
                                        if len(lineParts) == 3 and host is not None:
                                                host.lastReached = datetime.fromtimestamp(int(lineParts[1]))
                                                host.lastReachAttempt = datetime.fromtimestamp(int(lineParts[2]))
                                        if len(lineParts) == 2 and host is not None:
                                                host.lastReached = datetime.fromtimestamp(int(lineParts[1]))
                                        else:
                                                # Set the lastReached time to now to give us something
                                                # to guage reachability in the future for cleaning up.
                                                host.lastReached = now
                                                host.lastReachAttempt = now
                                        
                                        self.hosts.add(host)

        def parseMessageLines(self, linesRead):
                parsed = dict()
                for line in linesRead:
                        # According to the protocol, each line must follow this format:
                        # Field: value\r\n
                        # or
                        # Field\r\n
                        #
                        # "value" is arbitrary and may also contain the ":" character,
                        # but we only split the string by the first occurrence of ":".
                        #
                        # "Field" is case-insensitive.
                        lineParts = line.split(":", 1)
                        if len(lineParts) == 2:
                                field = lineParts[0].strip().lower()
                                val = lineParts[1].strip()
                                if len(field) > 0 and len(val) > 0:
                                        parsed[field] = val
                        elif len(lineParts) == 1:
                                # No value.
                                field = lineParts[0].strip()
                                parsed[field] = None

                return parsed
        
        def parseRecipient(self, recipient):
                # According to the protocol, a recipient may be of these formats:
                # 1) @example (a user but no service identifier)
                # 2) service_xyz@example (with both a service identifier and a user)
                # 3) service_xyz (no user identifier, i.e. addressed to the local user)
                #
                # "example" is arbitrary and may also contain the "@" character, but we only
                # split the string by the first occurrence of "@".
                #
                # User and service identifiers are case-insensitive.
                lineParts = recipient.split("@", 1)
                if len(lineParts) == 2:
                        return MessageRecipient(service=lineParts[0].strip().lower(), user=lineParts[1].strip().lower())
                else:
                        return MessageRecipient(service=recipient.strip().lower())

        def pingHosts(self):
                # Broadcast once to discover hosts on our LAN.
                self.localBroadcast()

                while 1:
                        # Make a list copy of the set to allow for mutation.
                        for host in list(self.hosts):
                                now = datetime.now()
                                # No use pinging a peer again if they just pinged us. Allow for a gap.
                                if host.lastReached is None or \
                                   now - timedelta(seconds=self.INTERVAL_HOST_PING) > host.lastReached <= now:
                                        print(f"--[PINGING {host.address}:{host.port}]--")
                                        message = ProtocolMessage()
                                        message.type = ProtocolMessageType.PING
                                        self.sendServerMessage(host, message)
                                
                                # If a host hasn't responded to a ping for a duration more than three intervals
                                # then they're likely unreachable.
                                if host.reachable and \
                                   now - timedelta(seconds=self.INTERVAL_HOST_PING*3) > host.lastReached <= now:
                                        print(f"--[{host} IS UNREACHABLE]--")
                                        host.reachable = False
                                
                                # Check if this is a dead host.
                                if now - host.lastReached > self.AGE_HOST:
                                        print(f"--[{host} IS DEAD]--")
                                        self.hosts.discard(host)
                        
                        # Dump the set to the disk.
                        self.dumpHosts()
                        time.sleep(self.INTERVAL_HOST_PING)
                        if len(self.hosts) == 0:
                                # Continuously broadcast if we have no known peers.
                                self.localBroadcast()
                        
        def pollInbox(self):
                while 1:
                        # Use a copy of the inbox container as it may get
                        # modified by the message handling methods.
                        inboxCopy = set(self.inbox)
                        for message in inboxCopy:
                                self.handleInboundMessage(message)

                        time.sleep(self.INTERVAL_POLL_INBOX)

        def pollOutbox(self):
                while 1:
                        # Use a copy of the outbox container as it may get
                        # modified by the message handling methods.
                        outboxCopy = set(self.outbox)
                        for message in outboxCopy:
                                user = message.recipient.user.hex()
                                try:
                                        recipientBlock = IdentityBlock.read(self.blockPath / (user + "." + FILE_EXT_NCLE))
                                        if recipientBlock is not None:
                                                self.handleOutboundMessage(message)
                                except Exception as e:
                                        print("Messenger.pollPending():", e)

                        time.sleep(self.INTERVAL_POLL_OUTBOX)

        def probe(self, user):
                if user is None:
                        raise ValueError("Messenger.probe(1): user is None")

                with open(PATH_NCLE_FILE_PROBES, "a") as probesFile:
                        probesFile.write(f"{user}\n")
        
        def processHost(self, hostStr):
                if hostStr is None:
                        raise ValueError("Messenger.processHost(1): hostStr is None")
                
                lineParts = hostStr.strip().split(" ")
                if len(lineParts) > 0:
                        # Each line can contain an IP address, a port (concatenated by a colon), 
                        # and a space followed by the last time that the host was reachable and
                        # the last time reachability was attempted.
                        host = None
                        hostAddress = lineParts[0]
                        addressParts = hostAddress.split(":")
                        now = datetime.now()

                        if len(addressParts) == 2:
                                address = addressParts[0]
                                port = int(addressParts[1])
                                # Check if one of the default hosts is the current machine
                                # in which case don't add it to the set.
                                if address != self.localAddress():
                                        host = Host(address, port)

                        if host is not None:
                                if len(lineParts) == 3:
                                        host.lastReached = datetime.fromtimestamp(int(lineParts[1]))
                                        host.lastReachAttempt = datetime.fromtimestamp(int(lineParts[2]))
                                elif len(lineParts) == 2:
                                        host.lastReached = datetime.fromtimestamp(int(lineParts[1]))
                                else:
                                        # Set the lastReached time to now to give us something
                                        # to guage reachability in the future for cleaning up.
                                        host.lastReached = now
                                        host.lastReachAttempt = now

                                hostExists = False
                                for host in self.hosts:
                                        if host == host:
                                                hostExists = True
                                                break
                                if not hostExists:
                                        self.hosts.add(host)

        def processWhoAmIResponses(self):
                neighbours = self.reachableHosts()
                if len(self.whoAmIResponses) == min(self.ADDRESS_DISCOVERY_NEIGHBOURS, len(neighbours)):
                        probableAddress = mode(self.whoAmIResponses)
                        if probableAddress != self.localAddress():
                                self.publicAddress = probableAddress

        def purgeReceipts(self):
                while 1:
                        time.sleep(self.INTERVAL_RECEIPT_PURGE)

                        files = [filename for filename in os.listdir(PATH_XTALK_DIR_RECEIPTS) if os.path.isfile(os.path.join(PATH_XTALK_DIR_RECEIPTS, filename)) and filename[0] != "."]
                        for receiptFilePath in files:
                                receipt = MessageReceipt.read(receiptFilePath)
                                currentTime = datetime.now()
                                if currentTime - receipt.timestamp > self.AGE_RECEIPT:
                                        self.deleteFromReceiptsDirectory(receipt.originalMessageIdentifier.hex())
        
        def readAppMessage(self, connection):
                lines = []
                line = ""
                try:
                        while "\r\n\r\n" not in line:
                                buffer = connection.recv(1)
                                if len(buffer) > 0:
                                        line += buffer.decode()
                                else:
                                        # No more data from this client (due to a disconnection).
                                        break
                        
                        if "\r\n" in line:
                                lineParts = line.split("\r\n")
                                for part in lineParts:
                                        # strip() to get rid of \r\n.
                                        part = part.strip()
                                        if len(part) > 0:
                                                lines.append(part)
                except Exception as e:
                        print("Messenger.readAppMessage(1):", e)
                        
                return lines
        
        def readBlock(self, messageIdentifier):
                if messageIdentifier is None:
                        raise ValueError("Messenger.readBlock(1): messageIdentifier is None")
                elif not isinstance(messageIdentifier, str):
                        raise TypeError("Messenger.readBlock(1): messageIdentifier is not an instance of str")
                
                # NOTE:
                # This method is not equivalent to MessageBlock.read(1), which returns a MessageBlock object.
                # This method only returns the raw byte array of a block as it reads it from the file.
                try:
                        blockFilePath = os.path.join(PATH_XTALK_DIR_OTHER, messageIdentifier + "." + FILE_EXT_XTALK)
                        with open(blockFilePath, mode="rb") as file:
                                return bytearray(file.read())
                except EnvironmentError:
                        return None
        
        def readNCLEConfig(self):
                with open(PATH_NCLE_FILE_CONF, "r") as file:
                        configLines = file.read().strip().split("\n")
                        for line in configLines:
                                if not line.startswith(CONF_SYMBOL_COMMENT):
                                        config = line.split(" ", 1)
                                        key = config[0].strip()
                                        if key == CONF_NCLE_KEY_BLOCK_PATH:
                                                self.blockPath = Path(config[1].strip())
                                        elif key == CONF_NCLE_KEY_ID_BLOB:
                                                self.isBlobMode = bool(strtobool(config[1].strip()))
                                        elif key == CONF_NCLE_KEY_ID_PATH:
                                                self.idPath = Path(config[1].strip())
                                        elif key == CONF_NCLE_KEY_KEY_PATH:
                                                self.privateKeyPath = Path(config[1].strip())
        
        def readHosts(self):
                with open(PATH_XTALK_FILE_HOSTS) as hostsFile:
                        # Clear the current set.
                        self.hosts.clear()
                        self.parseHosts(hostsFile)

                        if len(self.hosts) == 0:
                                # Use the hard-coded known hosts.
                                self.parseHosts(self.DEFAULT_HOSTS)

        def readIdentity(self):
                if self.isBlobMode:
                        with open(self.idPath, "rb") as file:
                                identifier = file.read()
                else:
                        with open(self.idPath, "r") as file:
                                identifier = file.read().strip().lower()  # Nomicle is case-insensitive when it comes to identifiers.
                return identifier

        def readInbox(self):
                self.inbox.clear()

                files = [filename for filename in os.listdir(PATH_XTALK_DIR_INBOX) if os.path.isfile(os.path.join(PATH_XTALK_DIR_INBOX, filename)) and filename[0] != "."]
                for filename in files:
                        try:
                                block = MessageBlock.read(filename, location="inbox")
                                self.inbox.add(block)
                        except Exception as e:
                                print("Messenger.readInbox():", e)
        
        def readOutbox(self):
                self.outbox.clear()

                files = [filename for filename in os.listdir(PATH_XTALK_DIR_OUTBOX) if os.path.isfile(os.path.join(PATH_XTALK_DIR_OUTBOX, filename)) and filename[0] != "."]
                for filename in files:
                        try:
                                block = MessageBlock.read(filename, location="outbox")
                                self.outbox.add(block)
                        except Exception as e:
                                print("Messenger.readOutbox():", e)
        
        def readReceipt(self, originalMessageIdentifier):
                if originalMessageIdentifier is None:
                        raise ValueError("Messenger.readReceipt(1): originalMessageIdentifier is None")
                elif not isinstance(originalMessageIdentifier, str):
                        raise TypeError("Messenger.readReceipt(1): originalMessageIdentifier is not an instance of str")
                
                # NOTE:
                # This method is not equivalent to MessageReceipt.read(1), which returns a MessageReceipt object.
                # This method only returns the raw byte array of a receipt as it reads it from the file.
                try:
                        receiptFilePath = os.path.join(PATH_XTALK_DIR_RECEIPTS, originalMessageIdentifier + "." + FILE_EXT_XTALK_RECEIPT)
                        with open(receiptFilePath, mode="rb") as file:
                                return bytearray(file.read())
                except EnvironmentError:
                        return None
        
        def reachableHosts(self):
                reachable = []
                for host in self.hosts:
                        if host.reachable:
                                reachable.append(host)
                return reachable

        def registerAppInterests(self, app, interests):
                if app is None:
                        raise ValueError("Messenger.registerAppInterests(2): app is None")
                elif not isinstance(app, App):
                        raise TypeError("Messenger.registerAppInterests(2): app is not an instance of App")
                elif interests is None:
                        raise ValueError("Messenger.registerAppInterests(2): interests is None")

                interests = interests.split(",")
                # Start clean by removing this app from any current lists.
                for service in list(self.apps):
                        appList = [a for a in self.apps[service] if a != app]
                        # If the list is now empty, delete it.
                        # The wildcard list never gets deleted.
                        if service != ProtocolAppKey.WILDCARD_SERVICE and len(appList) == 0:
                                self.apps.pop(service)
                        else:
                                self.apps[service] = appList
                
                for service in interests:
                        service = service.strip().lower() # Service identifiers are case-insensitive.
                        if service in self.apps:
                                self.apps[service].append(app)
                        else:
                                self.apps[service] = [app]
        
        def routeMessage(self, message, sender):
                if message is None:
                        raise ValueError("Messenger.routeMessage(2): message is None")

                message = ProtocolMessage(data=message)
                if message.type == ProtocolMessageType.HOST:
                        if message.body is not None:
                                self.processHost(message.body.decode())
                elif message.type == ProtocolMessageType.MESSAGE:
                        block = MessageBlock.deserialise(message.body)
                        if block is not None:
                                # Update the last-exchange timestamp for this host.
                                for host in self.hosts:
                                        if host == sender:
                                                host.lastExchangeReceived = datetime.now()

                                if self.shouldAcceptBlock(block):
                                        # Check if this message was intended for us.
                                        if self.messageIsAddressedToLocal(block):
                                                print("--[RECEIVED MESSAGE BLOCK ADDRESSED TO LOCAL USER]--")
                                                self.inbox.add(block)
                                                block.dump(location="inbox")
                                        else:
                                                # If we don't have an existing copy of this block, chances are
                                                # it's a new message, so we seed it to help spread it quicker.
                                                existingCopy = self.readBlock(block.identifier.hex())
                                                if existingCopy is None:
                                                        self.seedBlock(block, excluding=[sender])
                                                block.dump()
                                else:
                                        # If the peer sent a block for which a receipt exists,
                                        # send them the receipt to let them know the message has
                                        # been delivered.
                                        existingReceipt = self.readReceipt(block.identifier.hex())
                                        # REMEMBER: readReceipt(1) returns bytes, not an object.
                                        if existingReceipt is not None:
                                                message = ProtocolMessage()
                                                message.type = ProtocolMessageType.RECEIPT
                                                message.body = existingReceipt
                                                self.sendServerMessage(sender, message)
                elif message.type == ProtocolMessageType.PING:
                        hostExists = False
                        for host in self.hosts:
                                if host == sender:
                                        sender = host
                                        hostExists = True
                                        break
                        if not hostExists:
                                self.hosts.add(sender)
                        # Update the reachability of the host.
                        if not sender.reachable:
                                sender.reachable = True
                                print(f"--[{sender} IS REACHABLE]--")
                                # Seed host IP addresses.
                                self.exchangeHostPool(sender)
                        # Send a pong.
                        response = ProtocolMessage()
                        response.type = ProtocolMessageType.PONG
                        self.sendServerMessage(sender, response)
                        # Next, send some blocks.
                        self.exchangeBlockPool(sender)
                elif message.type == ProtocolMessageType.PONG:
                        hostExists = False
                        for host in self.hosts:
                                if host == sender:
                                        host.lastReached = sender.lastReached
                                        host.lastReachAttempt = sender.lastReachAttempt
                                        sender = host
                                        hostExists = True
                                        break
                        if not hostExists:
                                self.hosts.add(sender)
                        # Update the reachability of the host.
                        if not sender.reachable:
                                sender.reachable = True
                                print(f"--[{sender} IS REACHABLE]--")
                                # Seed host IP addresses.
                                self.exchangeHostPool(sender)
                        # Send some blocks.
                        self.exchangeBlockPool(sender)
                elif message.type == ProtocolMessageType.RECEIPT:
                        receipt = MessageReceipt.deserialise(message.body)
                        if receipt is not None:
                                # Update the last-exchange timestamp for this host.
                                for host in self.hosts:
                                        if host == sender:
                                                host.lastExchangeReceived = datetime.now()
                                self.handleReceipt(receipt)
                elif message.type == ProtocolMessageType.WHO_AM_I:
                        response = ProtocolMessage()
                        response.type = ProtocolMessageType.YOU_ARE
                        response.body = sender.address.encode()
                        self.sendServerMessage(sender, response)
                elif message.type == ProtocolMessageType.YOU_ARE:
                        allegedAddress = message.body.decode()
                        if len(allegedAddress) > 0:
                                self.whoAmIResponses.append(allegedAddress)
                                self.processWhoAmIResponses()

        def seedBlock(self, block, excluding=None):
                if block is None:
                        raise ValueError("Messenger.seedBlock(2): block is None")
                elif not isinstance(block, MessageBlock):
                        raise TypeError("Messenger.seedBlock(2): block is not an instance of MessageBlock")

                message = ProtocolMessage()
                message.type = ProtocolMessageType.MESSAGE
                message.body = block.serialise()
                self.broadcast(message, excluding=excluding)

        def seedReceipt(self, receipt):
                if receipt is None:
                        raise ValueError("Messenger.seedReceipt(1): receipt is None")
                elif not isinstance(receipt, MessageReceipt):
                        raise TypeError("Messenger.seedReceipt(1): receipt is not an instance of MessageReceipt")
                
                message = ProtocolMessage()
                message.type = ProtocolMessageType.RECEIPT
                message.body = receipt.serialise()
                self.broadcast(message)

        def sendAppMessage(self, app, message):
                if app is None:
                        raise ValueError("Messenger.sendAppMessage(2): app is None")
                elif message is None:
                        raise ValueError("Messenger.sendAppMessage(2): message is None")
                
                try:
                        app.connection.sendall(f"{ProtocolAppKey.SENDER}: {message.senderRaw}".encode())
                        app.connection.sendall(self.FIELD_DELIMITER.encode())
                        app.connection.sendall(f"{ProtocolAppKey.MESSAGE_IDENTIFIER}: {message.identifier.hex()}".encode())
                        app.connection.sendall(self.FIELD_DELIMITER.encode())
                        if message.inReplyTo is not None:
                                app.connection.sendall(f"{ProtocolAppKey.REPLY_TO}: {message.inReplyTo.hex()}".encode())
                                app.connection.sendall(self.FIELD_DELIMITER.encode())
                        app.connection.sendall(f"{ProtocolAppKey.TIMESTAMP}: {message.timestamp}".encode())
                        app.connection.sendall(self.FIELD_DELIMITER.encode())
                        app.connection.sendall(f"{ProtocolAppKey.PAYLOAD}: {message.payload}".encode())
                        app.connection.sendall(self.FIELD_DELIMITER.encode())
                        app.connection.sendall(self.FIELD_DELIMITER.encode())
                except Exception as e:
                        print(e)
        
        def sendServerMessage(self, host, message):
                if host is None:
                        raise ValueError("Messenger.sendServerMessage(2): host is None")
                elif message is None:
                        raise ValueError("Messenger.sendServerMessage(2): message is None")
                
                try:
                        host.lastReachAttempt = datetime.now()
                        self.sockMessengers.sendto(message.serialise(), (host.address, host.port))
                except Exception as e:
                        print(e)
        
        def shouldAcceptBlock(self, block):
                if block is None:
                        raise ValueError("Messenger.shouldAcceptBlock(1): block is None")
                elif not isinstance(block, MessageBlock):
                        raise TypeError("Messenger.shouldAcceptBlock(1): block is not an instance of MessageBlock")

                # Check the timestamp. A block set more than 2 hours into the future 
                # or 15 days into the past is rejected.
                now = datetime.now()
                if block.timestamp > now + timedelta(hours=2) or \
                   block.timestamp < now - timedelta(days=15):
                        print("MESSAGE BLOCK TIMESTAMP IS BAD!")
                        return False
                
                existingReceipt = self.readReceipt(block.identifier.hex())
                if existingReceipt is None:
                        # Check the public key of the sender vs. the one in the doiminant 
                        # identity block.
                        senderIdentity = IdentityBlock.read(self.blockPath / (block.sender.hex() + "." + FILE_EXT_NCLE))
                        if senderIdentity is None:
                                return True
                        elif senderIdentity.publicKey.public_numbers() == block.senderPublicKey.public_numbers():
                                return True
                        else:
                                return False
                else:
                        return False
        
        def start(self):
                sys.setrecursionlimit(10000)
                self.bootstrap()

                self.userRawIdentifier = self.readIdentity()
                if self.userRawIdentifier is not None and len(self.userRawIdentifier) > 0:
                        self.userIdentifier = hashlib.sha256(self.userRawIdentifier.encode()).digest()
                else:
                        self.userIdentifier = None
                        self.userRawIdentifier = None

                self.privateKey = self.loadPrivateKey()
                # Spawn a different thread and do inter-messenger comms there.
                messengerThread = threading.Thread(target=self.listenForMessengers)
                messengerThread.daemon = True
                messengerThread.start()
                # Maintain peer heartbeats on a separate thread.
                pingingThread = threading.Thread(target=self.pingHosts)
                pingingThread.daemon = True
                pingingThread.start()
                # Poll the filesystem for undelivered app messages in the inbox.
                pollingInboxThread = threading.Thread(target=self.pollInbox)
                pollingInboxThread.daemon = True
                pollingInboxThread.start()
                # Poll the filesystem for recipient identity blocks of pending outbox messages.
                pollingOutboxThread = threading.Thread(target=self.pollOutbox)
                pollingOutboxThread.daemon = True
                pollingOutboxThread.start()
                # Periodically purge receipts of delivered messages.
                receiptPurgeThread = threading.Thread(target=self.purgeReceipts)
                receiptPurgeThread.daemon = True
                receiptPurgeThread.start()
                # Periodically check for the machine's public IP address.
                addressDiscoveryThread = threading.Thread(target=self.discoverPublicAddress)
                addressDiscoveryThread.daemon = True
                addressDiscoveryThread.start()
                # This final method call is blocking.
                self.listenForApps()


if __name__ == "__main__":
        messenger = Messenger()
        messenger.start()
