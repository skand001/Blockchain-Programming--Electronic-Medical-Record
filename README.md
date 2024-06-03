## - Blockchain Programming Assignment

This code implements the functionality required for the Blockchain Programming assignment, covering the following features:

## Part 1: Electronic Medical Records (EMR)

- Implements the `EMR` class with the specified constructor and `verify` method.
- Validates the length of `Dr_hash` and `patient_hash` to be 20 bytes.
- Verifies that `Dr_hash` is the SHA-1 hash of `Dr_public_key`.
- Checks that `prescription` is a string with a maximum of 200 bytes.
- Ensures that `nonce` is equal to `Dr_previous_nonce + 1`.
- Validates that `txid` is the hash of the other fields in the record.
- Verifies the signature using the doctor's public key.
- Implements the `create_signed_record` function to create a new signed EMR record.
- Includes test cases for valid record verification, invalid txid verification, invalid signature verification, invalid nonce verification, and invalid signature with a different key verification.

## Part 2: Blocks

- Implements the `UserState` class with the `nonce` field.
- Implements the `Block` class with the specified constructor and `verify_and_get_changes` method.
- Validates the block difficulty, block ID, number of records, miner public key hash length, and proof of work.
- Updates user states based on the records in the block.
- Implements the `calculate_block_id` method to calculate the block ID based on the specified fields and encoding.
- Implements the `verify_proof_of_work` method to verify the proof of work by comparing the block ID with the calculated target.
- Implements the `mine_block` function to produce a block that meets the proof of work criteria.
- Includes test cases for valid block verification, invalid block ID verification, and invalid difficulty verification.

## Additional Features

- Provides a `format_block` function to format the block details for better readability.
- Includes example usage code to demonstrate the mining of a block and printing the mined block details.

Note: The code assumes the presence of the `EMR` class from `cw2_part1.py` and uses the same cryptography library and hashing algorithms as in the previous part of the assignment.

Please refer to the code files `cw2_part1.py` and `cw2_part2.py` for the complete implementation and further details.