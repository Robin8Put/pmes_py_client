# Mock of the Python client for PMES

This client allows to work with [Profile Management EcoSystem (PMES)](https://github.com/Robin8Put/pmes):

- create client object
- set content in the blockchain
- get content from the blockchain
- set content description in the blockchain
- get content description from the blockchain
- change owner of data
- sell content

- `PMESClient` --- client module
    - `__init__` --- init class with host of server
    - `gen_keys` --- generate public / private keys and write to `keys.json`
    - `fill_form` --- fill information about user such as email, phone number and device id
    - `create_account` --- create new account
    - `get_account_data` --- get account info
    - `get_balance` --- get account balance
    - `get_data_from_blockchain` --- get content from blockchain
    - `post_data_to_blockchain` --- write content to blockchain
    - `get_last_block_id` --- get last blockid
    - `get_owner` --- get owner of content
    - `change_owner` --- change owner to new one by providing his public key
    - `set_content_description` --- set content description
    - `get_content_description` --- get content description
    - `get_access_string` --- get access string
    - `sell_content` --- sell content
- `account.json` --- contain user data (email, phone number and device id)
- `cookies.json` --- save hash and cid of stored content in PMES
- `generated.json` --- set of public and private keys. Used for choosing default value for changing owner, selling content, etc.
- `keys.json` --- contain user public and private keys

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

For running application run `python3` and initialize `PMESClient`.

```bash
from client import PMESClient
c = PMESClient()
```

Check client by running next command:

```bash
c.get_last_block_id()
```

Create account:

```bash
c.gen_keys()
c.fill_form()
c.create_account()
```

Result will be:

```bash
{
    'public_key': '04582af6644c05180b11198425349dc8cd8f06cbde67dd5152e1ab03a4e4080af4cd5748e7e7f1ffe3852db05758623aae4c93e8d59c876c293e52cdfcef25f6ab', 
    'email': 'test@gmail.com', 
    'device_id': 'some_id', 
    'count': '1', 
    'level': '2', 
    'id': 2, 'href': '/api/accounts/04582af6644c05180b11198425349dc8cd8f06cbde67dd5152e1ab03a4e4080af4cd5748e7e7f1ffe3852db05758623aae4c93e8d59c876c293e52cdfcef25f6ab', 
    'balance': 0, 
    'address': 'QUvEvQWiJz3iPBpvSQQPLC1xXA7T5V25Xp'
}
```

Write content to blockchain, wait until it writes them to the blockchain and return cid back to you (near 5 minutes). After that, add description:

```bash
c.post_data_to_blockchain()
c.get_data_from_blockchain()
c.set_content_description()
```

For changing owner you need to pass access string. The access string is any not empty string.

```bash
c.change_owner()
```
