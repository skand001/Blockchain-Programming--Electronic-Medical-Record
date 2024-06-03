#!/usr/bin/env python
# coding: utf-8

# IS71128A: BLOCKCHAIN PROGRAMMING (2023-24) Coursework 2
# Programming assignment Part 1: Electronic Medical Records
# Author: Sandor Kanda

# Library Imports
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import load_der_public_key, PublicFormat, Encoding
from cryptography.hazmat.primitives.asymmetric import utils, ec
import unittest

# Helper Functions

# SHA1 hash calculation
def calculate_sha1_hash(public_key):
    """
    Calculate the SHA-1 hash of the given public key.
    :param public_key: The public key to hash.
    :return: The SHA-1 hash of the public key.
    """
    digest = hashes.Hash(hashes.SHA1())
    digest.update(public_key)
    return digest.finalize()

# Transaction ID calculation
def calculate_txid(Dr_hash, Patient_hash, Dr_public_key, prescription, nonce, signature):
    """
    Calculate the transaction ID (txid) by hashing the given record fields.
    :param Dr_hash: The SHA-1 hash of the doctor's public key.
    :param Patient_hash: The SHA-1 hash of the patient's public key.
    :param Dr_public_key: The doctor's public key.
    :param prescription: The prescription details.
    :param nonce: The nonce value.
    :param signature: The signature of the record.
    :return: The transaction ID (txid) as a byte array.
    """
    digest = hashes.Hash(hashes.SHA256())
    digest.update(Dr_hash)
    digest.update(Patient_hash)
    digest.update(Dr_public_key)
    digest.update(prescription.encode('utf-8'))
    digest.update(nonce.to_bytes(8, byteorder='little', signed=False))
    digest.update(signature)
    return digest.finalize()

# Signature hash calculation
def calculate_signature_hash(Dr_hash, Patient_hash, prescription, nonce):
    """
    Calculate the signature hash by hashing the given record fields.
    :param Dr_hash: The SHA-1 hash of the doctor's public key.
    :param Patient_hash: The SHA-1 hash of the patient's public key.
    :param prescription: The prescription details.
    :param nonce: The nonce value.
    :return: The signature hash as a byte array.
    """
    digest = hashes.Hash(hashes.SHA256())
    digest.update(Dr_hash)
    digest.update(Patient_hash)
    digest.update(prescription.encode('utf-8'))
    digest.update(nonce.to_bytes(8, byteorder='little', signed=False))
    return digest.finalize()

# EMR Class
class EMR:
    """
    Represents an Electronic Medical Record (EMR).
    """
    def __init__(self, Dr_hash, Patient_hash, Dr_public_key, prescription, nonce, signature, txid):
        """
        Initialize an EMR object with the given parameters.
        :param Dr_hash: The SHA-1 hash of the doctor's public key.
        :param Patient_hash: The SHA-1 hash of the patient's public key.
        :param Dr_public_key: The doctor's public key.
        :param prescription: The prescription details.
        :param nonce: The nonce value.
        :param signature: The signature of the record.
        :param txid: The transaction ID (txid) of the record.
        """
        self.Dr_hash = Dr_hash
        self.Patient_hash = Patient_hash
        self.Dr_public_key = Dr_public_key
        self.prescription = prescription
        self.nonce = nonce
        self.signature = signature
        self.txid = txid

    def verify(self, Dr_previous_nonce):
        """
        Verify the integrity and authenticity of the EMR.
        :param Dr_previous_nonce: The previous nonce used by the doctor.
        :raises Exception: If any of the verification checks fail.
        """
        if len(self.Dr_hash) != 20 or len(self.Patient_hash) != 20:
            raise Exception("Hash is wrong length.")

        if calculate_sha1_hash(self.Dr_public_key) != self.Dr_hash:
            raise Exception("Invalid Dr_public_key.")

        if not isinstance(self.prescription, str) or len(self.prescription.encode('utf-8')) > 200:
            raise Exception("Invalid prescription.")

        if self.nonce != Dr_previous_nonce + 1:
            raise Exception("Invalid nonce.")

        if self.txid != calculate_txid(self.Dr_hash, self.Patient_hash, self.Dr_public_key, self.prescription, self.nonce, self.signature):
            raise Exception("Invalid txid.")

        signature_hash = calculate_signature_hash(self.Dr_hash, self.Patient_hash, self.prescription, self.nonce)
        key = load_der_public_key(self.Dr_public_key)

        try:
            key.verify(self.signature, signature_hash, ec.ECDSA(utils.Prehashed(hashes.SHA256())))
        except Exception as e:
            raise Exception(f"Invalid signature: {str(e)}")

# The create_signed_record function
def create_signed_record(Dr_private_key, Patient_hash, prescription, nonce):
    """
    Create a signed EMR record.
    :param Dr_private_key: The doctor's private key.
    :param Patient_hash: The SHA-1 hash of the patient's public key.
    :param prescription: The prescription details.
    :param nonce: The nonce value.
    :return: The signed EMR record.
    """
    Dr_public_key = Dr_private_key.public_key().public_bytes(encoding=Encoding.DER, format=PublicFormat.SubjectPublicKeyInfo)
    Dr_hash = calculate_sha1_hash(Dr_public_key)
    signature_hash = calculate_signature_hash(Dr_hash, Patient_hash, prescription, nonce)
    signature = Dr_private_key.sign(signature_hash, ec.ECDSA(utils.Prehashed(hashes.SHA256())))
    txid = calculate_txid(Dr_hash, Patient_hash, Dr_public_key, prescription, nonce, signature)

    return EMR(Dr_hash, Patient_hash, Dr_public_key, prescription, nonce, signature, txid)

# Testing
class TestEMR(unittest.TestCase):
    """
    Unit tests for the EMR class and related functions.
    """
    def setUp(self):
        """
        Set up the test environment.
        """
        self.Dr_private_key = ec.generate_private_key(ec.SECP256K1)
        self.Patient_hash = b'0123456789abcdef0123'
        self.prescription = 'test_prescription'
        self.nonce = 1

    def test_valid_record(self):
        """
        Test the creation and verification of a valid EMR record.
        """
        record = create_signed_record(self.Dr_private_key, self.Patient_hash, self.prescription, self.nonce)
        Dr_previous_nonce = 0
        record.verify(Dr_previous_nonce)

    def test_invalid_txid(self):
        """
        Test the verification of an EMR record with an invalid txid.
        """
        record = create_signed_record(self.Dr_private_key, self.Patient_hash, self.prescription, self.nonce)
        record.prescription = 'modified_prescription'
        Dr_previous_nonce = 0
        with self.assertRaises(Exception):
            record.verify(Dr_previous_nonce)

    def test_invalid_signature(self):
        """
        Test the verification of an EMR record with an invalid signature.
        """
        record = create_signed_record(self.Dr_private_key, self.Patient_hash, self.prescription, self.nonce)
        record.prescription = 'modified_prescription'
        record.txid = calculate_txid(record.Dr_hash, record.Patient_hash, record.Dr_public_key, record.prescription, record.nonce, record.signature)
        Dr_previous_nonce = 0
        with self.assertRaises(Exception):
            record.verify(Dr_previous_nonce)

    def test_invalid_nonce(self):
        """
        Test the verification of an EMR record with an invalid nonce.
        """
        record = create_signed_record(self.Dr_private_key, self.Patient_hash, self.prescription, self.nonce)
        Dr_previous_nonce = 5
        with self.assertRaises(Exception):
            record.verify(Dr_previous_nonce)

    def test_invalid_signature_different_key(self):
        """
        Test the verification of an EMR record with an invalid signature generated using a different key.
        """
        Dr_private_key_A = ec.generate_private_key(ec.SECP256K1)
        Dr_private_key_B = ec.generate_private_key(ec.SECP256K1)
        record = create_signed_record(Dr_private_key_A, self.Patient_hash, self.prescription, self.nonce)
        signature_hash = calculate_signature_hash(record.Dr_hash, record.Patient_hash, record.prescription, record.nonce)
        new_signature = Dr_private_key_B.sign(signature_hash, ec.ECDSA(utils.Prehashed(hashes.SHA256())))
        record.signature = new_signature
        record.txid = calculate_txid(record.Dr_hash, record.Patient_hash, record.Dr_public_key, record.prescription, record.nonce, record.signature)
        Dr_previous_nonce = 0
        with self.assertRaises(Exception):
            record.verify(Dr_previous_nonce)

if __name__ == '__main__':
    unittest.main()