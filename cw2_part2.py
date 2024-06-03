#!/usr/bin/env python
# coding: utf-8

# IS71128A: BLOCKCHAIN PROGRAMMING (2023-24) Coursework 2
# Programming assignment Part 2: Blocks 
# Author: Sandor Kanda

# Library Imports
import time
import multiprocessing
from cw2_part1 import EMR, calculate_sha1_hash, calculate_txid
from cryptography.hazmat.primitives import hashes
import hashlib
import unittest

class UserState:
    """
    Represents the state of a user.
    """
    def __init__(self, nonce):
        """
        Initialize a UserState object with the given nonce.
        :param nonce: The most recently used nonce of the user.
        """
        self.nonce = nonce

class Block:
    """
    Represents a block in the blockchain.
    """
    def __init__(self, previous, height, miner, records, timestamp, difficulty, block_id, nonce):
        """
        Initialize a Block object with the given parameters.
        :param previous: The block ID of the previous block.
        :param height: The height of the block in the blockchain.
        :param miner: The public key hash of the miner.
        :param records: The list of records included in the block.
        :param timestamp: The timestamp of the block.
        :param difficulty: The difficulty of the proof-of-work.
        :param block_id: The block ID.
        :param nonce: The nonce value used in the proof-of-work.
        """
        self.previous = previous
        self.height = height
        self.miner = miner
        self.records = records
        self.timestamp = timestamp
        self.difficulty = difficulty
        self.block_id = block_id
        self.nonce = nonce

    def verify_and_get_changes(self, difficulty, previous_user_states):
        """
        Verify the block and get the changes in user states.
        :param difficulty: The expected difficulty of the block.
        :param previous_user_states: The previous user states before the block.
        :return: The updated user states after the block.
        :raises Exception: If any of the verification checks fail.
        """
        if self.difficulty != difficulty:
            raise Exception("Invalid block difficulty")

        if self.block_id != self.calculate_block_id():
            raise Exception("Invalid block ID")

        if len(self.records) > 25:
            raise Exception("Block contains too many records")

        if len(self.miner) != 20:
            raise Exception("Invalid miner public key hash length")

        if not self.verify_proof_of_work():
            raise Exception("Block does not meet the required proof of work")

        updated_user_states = {}
        for record in self.records:
            sender_hash = record.Dr_hash
            if sender_hash not in updated_user_states:
                if sender_hash in previous_user_states:
                    updated_user_states[sender_hash] = UserState(previous_user_states[sender_hash].nonce)
                else:
                    updated_user_states[sender_hash] = UserState(0)

            try:
                record.verify(updated_user_states[sender_hash].nonce)
                updated_user_states[sender_hash].nonce += 1
            except Exception as e:
                raise Exception(f"Invalid record: {str(e)}")

        return updated_user_states

    def calculate_block_id(self):
        """
        Calculate the block ID by hashing the block fields.
        :return: The block ID as a byte array.
        """
        sha256 = hashlib.sha256()

        sha256.update(self.previous)
        sha256.update(self.miner)

        for record in self.records:
            sha256.update(record.txid)

        sha256.update(self.timestamp.to_bytes(8, byteorder='little', signed=False))
        sha256.update(self.difficulty.to_bytes(16, byteorder='little', signed=False))
        sha256.update(self.nonce.to_bytes(8, byteorder='little', signed=False))

        return sha256.digest()

    def verify_proof_of_work(self):
        """
        Verify the proof-of-work of the block.
        :return: True if the proof-of-work is valid, False otherwise.
        """
        target = 2 ** 256 // self.difficulty
        block_id_int = int.from_bytes(self.block_id, byteorder='big')

        return block_id_int <= target

def mine_block(previous, height, miner, transactions, timestamp, difficulty):
    """
    Mine a block by finding a valid nonce that satisfies the proof-of-work.
    :param previous: The block ID of the previous block.
    :param height: The height of the block in the blockchain.
    :param miner: The public key hash of the miner.
    :param transactions: The list of transactions to include in the block.
    :param timestamp: The timestamp of the block.
    :param difficulty: The difficulty of the proof-of-work.
    :return: The mined block.
    """
    nonce = 0

    while True:
        block = Block(previous, height, miner, transactions, timestamp, difficulty, None, nonce)
        block.block_id = block.calculate_block_id()

        if block.verify_proof_of_work():
            return block

        nonce += 1

def mine_block_worker(previous, height, miner, transactions, timestamp, difficulty, block_found, nonce, block_id):
    """
    Worker function for mining a block in parallel.
    :param previous: The block ID of the previous block.
    :param height: The height of the block in the blockchain.
    :param miner: The public key hash of the miner.
    :param transactions: The list of transactions to include in the block.
    :param timestamp: The timestamp of the block.
    :param difficulty: The difficulty of the proof-of-work.
    :param block_found: A shared value to indicate if a block has been found.
    :param nonce: A shared value to store the nonce.
    :param block_id: A shared array to store the block ID.
    """
    while not block_found.value:
        block = Block(previous, height, miner, transactions, timestamp, difficulty, bytes(32), nonce.value)
        block_id_candidate = block.calculate_block_id()
        target = 2 ** 256 // difficulty
        if int.from_bytes(block_id_candidate, byteorder='big') <= target:
            with block_found.get_lock():
                if not block_found.value:
                    block_found.value = True
                    block_id[:] = block_id_candidate
                    return
        with nonce.get_lock():
            nonce.value += 1

def mine_block(previous, height, miner, transactions, timestamp, difficulty):
    """
    Mine a block by finding a valid nonce that satisfies the proof-of-work using parallel processing.
    :param previous: The block ID of the previous block.
    :param height: The height of the block in the blockchain.
    :param miner: The public key hash of the miner.
    :param transactions: The list of transactions to include in the block.
    :param timestamp: The timestamp of the block.
    :param difficulty: The difficulty of the proof-of-work.
    :return: The mined block.
    """
    block_found = multiprocessing.Value('b', False)
    nonce = multiprocessing.Value('L', 0)
    block_id = multiprocessing.Array('B', 32)

    num_processes = multiprocessing.cpu_count()
    processes = []

    for _ in range(num_processes):
        process = multiprocessing.Process(target=mine_block_worker, args=(previous, height, miner, transactions, timestamp, difficulty, block_found, nonce, block_id))
        process.start()
        processes.append(process)

    for process in processes:
        process.join()

    return Block(previous, height, miner, transactions, timestamp, difficulty, bytes(block_id), nonce.value)

# Testing
class TestBlock(unittest.TestCase):
    """
    Unit tests for the Block class and related functions.
    """
    def test_valid_block(self):
        """
        Test the creation and verification of a valid block.
        """
        miner = b'miner_public_key_hash'
        previous = b'\x00' * 32
        transactions = []
        timestamp = 123456789
        difficulty = 500

        mined_block = mine_block(previous, 1, miner, transactions, timestamp, difficulty)

        self.assertEqual(mined_block.previous, previous)
        self.assertEqual(mined_block.height, 1)
        self.assertEqual(mined_block.miner, miner)
        self.assertEqual(mined_block.records, transactions)
        self.assertEqual(mined_block.timestamp, timestamp)
        self.assertEqual(mined_block.difficulty, difficulty)
        self.assertTrue(mined_block.verify_proof_of_work())

    def test_invalid_block_id(self):
        """
        Test the verification of a block with an invalid block ID.
        """
        miner = b'miner_public_key_hash'
        previous = b'\x00' * 32
        transactions = []
        timestamp = 123456789
        difficulty = 500

        mined_block = mine_block(previous, 1, miner, transactions, timestamp, difficulty)
        mined_block.block_id = b'invalid_block_id'

        with self.assertRaises(Exception) as context:
            mined_block.verify_and_get_changes(difficulty, {})

        self.assertEqual(str(context.exception), "Invalid block ID")

    def test_invalid_difficulty(self):
        """
        Test the verification of a block with an invalid difficulty.
        """
        miner = b'miner_public_key_hash'
        previous = b'\x00' * 32
        transactions = []
        timestamp = 123456789
        difficulty = 500

        mined_block = mine_block(previous, 1, miner, transactions, timestamp, difficulty)

        with self.assertRaises(Exception) as context:
            mined_block.verify_and_get_changes(difficulty + 1, {})

        self.assertEqual(str(context.exception), "Invalid block difficulty")

if __name__ == '__main__':
    # Example usage of the mine_block function

    miner = b'miner_public_key_hash'
    previous = b'\x00' * 32
    transactions = []
    timestamp = int(time.time())
    difficulty = 100_000

    start_time = time.time()
    mined_block = mine_block(previous, 1, miner, transactions, timestamp, difficulty)
    end_time = time.time()

    print("\n-> Mined Block Details:")
    print("Previous block ID:", mined_block.previous.hex())
    print("Height:", mined_block.height)
    print("Miner address:", mined_block.miner.hex())
    print("Number of transactions:", len(mined_block.records))
    print("Timestamp:", mined_block.timestamp)
    print("Difficulty:", mined_block.difficulty)
    print("Block ID:", mined_block.block_id.hex())
    print("Nonce:", mined_block.nonce)
    print(f"Mining time: {end_time - start_time:.2f} seconds")

    # Run the tests
    unittest.main()