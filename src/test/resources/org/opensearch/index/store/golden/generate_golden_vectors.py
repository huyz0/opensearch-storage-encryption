#!/usr/bin/env python3
# Copyright OpenSearch Contributors
# SPDX-License-Identifier: Apache-2.0
"""
Independent reference implementation of the OSEF v2 on-disk format, used to
generate the known-answer vectors in HkdfKeyDerivationKnownAnswerTests,
ChunkCipherKnownAnswerTests and
EncryptionFooterKnownAnswerTests, and the
committed golden file golden-v2.osef.

v2 layout: [ciphertext][one 16-byte GCM tag per 8 KiB chunk][footer]. Each chunk
is sealed with AES-256-GCM under the file key, nonce 00000000 || chunk index.

It deliberately shares no code with the plugin: HKDF is written out from
RFC 5869 with Python's hmac module and AES-GCM comes from the `cryptography`
package. If the Java implementation and this script ever disagree, the
on-disk format has changed and existing encrypted indices may no longer be
readable.

Usage: python3 generate_golden_vectors.py [output-dir]
Requires: pip install cryptography
"""
import hashlib
import hmac
import os
import struct
import sys

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

MASTER_KEY = bytes(range(0x00, 0x20))  # 32 bytes
MESSAGE_ID = bytes(range(0xA0, 0xB0))  # 16 bytes
ALGORITHM_ID = 1  # AES_256_GCM_CTR
MAGIC = b"OSEF"
GOLDEN_PLAINTEXT_LENGTH = 20000  # two full chunks and a 3616-byte tail


def hkdf_sha384(salt, ikm, info, length):
    # Note the argument order used by HkdfKeyDerivation: the master key is the
    # HKDF salt and the messageId is the input keying material.
    prk = hmac.new(salt, ikm, hashlib.sha384).digest()
    okm, t, i = b"", b"", 1
    while len(okm) < length:
        t = hmac.new(prk, t + info + bytes([i]), hashlib.sha384).digest()
        okm += t
        i += 1
    return okm[:length]


def file_key(master_key, message_id):
    return hkdf_sha384(master_key, message_id, b"file-encryption", 32)


def frame_base_iv(master_key, message_id, frame_number):
    # HKDF with a "frame-N" context. No longer used by the file format; kept as an
    # extra HKDF vector for HkdfKeyDerivationKnownAnswerTests.
    return hkdf_sha384(master_key, message_id, b"frame-%d" % frame_number, 16)


def translog_base_iv(master_key, translog_uuid):
    padded = translog_uuid.encode("utf-8")[:16].ljust(16, b"\x00")
    return hkdf_sha384(master_key, padded, b"translog-base-iv", 16)


CHUNK_SIZE = 1 << 13  # ChunkCipher.CHUNK_SIZE


def chunk_nonce(chunk_index):
    # ChunkCipher: four zero bytes || big-endian 64-bit chunk index.
    return b"\x00" * 4 + struct.pack(">Q", chunk_index)


def seal_chunks(key, plaintext):
    """Seals plaintext chunk by chunk; returns (ciphertext, [tags])."""
    ciphertext, tags = b"", []
    for i in range(0, len(plaintext), CHUNK_SIZE):
        sealed = AESGCM(key).encrypt(chunk_nonce(i // CHUNK_SIZE), plaintext[i : i + CHUNK_SIZE], None)
        ciphertext += sealed[:-16]
        tags.append(sealed[-16:])
    return ciphertext, tags


def golden_plaintext(length):
    return bytes((i * 31 + 7) & 0xFF for i in range(length))


def footer_bytes(key, message_id, data_length):
    body = struct.pack(">q", data_length)
    body += struct.pack(">i", CHUNK_SIZE)
    body += message_id
    body += b""  # KeyMetadata (empty)
    body += struct.pack(">h", 0)  # KeyMetadataLength
    body += struct.pack(">h", ALGORITHM_ID)
    body += struct.pack(">i", 16 + len(body) + 4 + 4)  # FooterLength incl. auth tag
    body += MAGIC
    footer_nonce = b"\xff" * 8 + b"\x00" * 4
    auth_tag = AESGCM(key).encrypt(footer_nonce, b"", body)  # empty plaintext, footer as AAD
    return auth_tag + body


def main():
    out_dir = sys.argv[1] if len(sys.argv) > 1 else os.path.dirname(os.path.abspath(__file__))
    fk = file_key(MASTER_KEY, MESSAGE_ID)
    iv0 = frame_base_iv(MASTER_KEY, MESSAGE_ID, 0)
    iv1 = frame_base_iv(MASTER_KEY, MESSAGE_ID, 1)
    print("fileKey            ", fk.hex())
    print("frameBaseIV(0)     ", iv0.hex())
    print("frameBaseIV(1)     ", iv1.hex())
    print("hkdf(49, ctx)      ", hkdf_sha384(MASTER_KEY, MESSAGE_ID, b"known-answer-test", 49).hex())
    print("translogIV(short)  ", translog_base_iv(MASTER_KEY, "short-uuid").hex())
    print("translogIV(long)   ", translog_base_iv(MASTER_KEY, "8rKGBKWtR9S2bIZ_hXlTQw-trailing").hex())

    chunk_ct, chunk_tags = seal_chunks(fk, golden_plaintext(CHUNK_SIZE + 100))
    print("chunkNonce(0x0102030405060708)", chunk_nonce(0x0102030405060708).hex())
    print("chunk0 ct[0:16]    ", chunk_ct[:16].hex())
    print("chunk0 tag         ", chunk_tags[0].hex())
    print("chunk1 ct[0:16]    ", chunk_ct[CHUNK_SIZE : CHUNK_SIZE + 16].hex())
    print("chunk1 tag         ", chunk_tags[1].hex())

    plaintext = golden_plaintext(GOLDEN_PLAINTEXT_LENGTH)
    ciphertext, tags = seal_chunks(fk, plaintext)
    footer = footer_bytes(fk, MESSAGE_ID, len(plaintext))
    print("golden ct[0:32]    ", ciphertext[:32].hex())
    for i, tag in enumerate(tags):
        print("golden tag %d       " % i, tag.hex())
    print("footer (%d bytes)  " % len(footer), footer.hex())

    with open(os.path.join(out_dir, "golden-v2.osef"), "wb") as f:
        f.write(ciphertext + b"".join(tags) + footer)


if __name__ == "__main__":
    main()
