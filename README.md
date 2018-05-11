# Mock of the Python client for PMES

This client allows to work with [Profile Management EcoSystem (PMES)](https://github.com/Robin8Put/pmes):

- create client object
	- registration
	- authorization
- then you can:
	- save data in blockchain
	- get data from blockchain
	- get data owner wallet address
	- set/get data description

- `bip32keys` --- library for generating public / private keys / blockchain address
    - `bip32keys` --- contain `Bip32Keys` class which allows generate public / private keys and sign / verify messages
        - `__init__` --- init class with `entropy` or `private_key` parameter
        - `init_from_entropy` --- generate public / private keys based on entropy
        - `init_from_private_key` --- generate public / private keys based on private key
        - `get_public_key` --- return generated public key
        - `get_private_key` --- return generated private key
        - `get_uncompressed_public_key` --- return generated uncompressed public key
        - `sign_msg` --- sign message with private_key
        - `sign_message` --- static function
        - `verify_msg` --- verify message with signature and public_key
        - `verify_message` --- static function
        - `to_uncompressed_public_key` --- convert public key to uncompressed public key
        - `to_compressed_public_key` --- convert uncompressed public key to public key
    - `bip32NetworkKeys` --- contain `Bip32NetworkKeys` class which was based on `Bip32Keys`
        - `__init__` --- init class with `wif` or `entropy` or `private_key` parameter
        - `get_wif` --- return generated wif
        - `wif_to_private_key` --- convert wif to private key
        - `private_key_to_wif` --- convert private key to wif
    - `bip32addresses` --- contain `Bip32Addresses` class which was based on `Bip32NetworkKeys`
        - `__init__` --- init class with `wif` or `entropy` or `private_key` parameter, `magic_byte` parameter should be passed also
        - `get_hex_address` --- return hex address generated based on public key
        - `get_blockchain_address` --- blockchain address generated based on hex address
        - `public_key_to_hex_address` --- convert public key to hex address
        - `hex_address_to_blockchain_address` --- convert hex address to blockchain address
        - `address_to_hex` --- convert address to hex format. Drop magic byte and checksum
        - `is_valid_address` --- check is address valid
        - `get_magic_byte` --- return magic byte
- `qtum_utils` --- packet that contains class `Qtum` which was based on the `Bip32Addresses`
    - `get_qtum_address` --- return qtum address
    - `hex_to_qtum_address` --- convert hex to qtum address
    - `public_key_to_qtum_address` --- convert public key to qtum address
    - `is_valid_qtum_address` --- check is qtum address valid

## Installation

Clone sources from git:

```bash
git clone https://github.com/Robin8Put/pmes_py_client.git
```

Create virtualenv and install needed libraries from the `requirements.txt`:

```bash
cd balance
virtualenv --python=python3.6 venv
source venv/bin/activate
pip3 install -r requirements.txt
```

## Running Client module

For running application run bash command:

```bash
python3 main.py
```