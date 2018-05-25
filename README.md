# Mock of the Python client for PMES

This client allows to work with [Profile Management EcoSystem (PMES)](https://github.com/Robin8Put/pmes):

- create client object
- set content in the blockchain
- get content from the blockchain
- set content description in the blockchain
- get content description from the blockchain
- set content price
- get content price
- sell content
- view all content descriptions

- `PMESClient` --- client module
    - `__init__` --- init class with server host
    - `help` --- show all commands
    - `gen_keys` --- generate public / private keys and write to `keys.json`
    - `fill_form` --- fill information about user such as email, phone number and device id
    - `create_account` --- create new account
    - `get_account_data` --- get account info
    - `get_data_from_blockchain` --- get content from blockchain
    - `post_data_to_blockchain` --- write content to blockchain
    - `get_content_description` --- get content description
    - `set_content_description` --- set content description
    - `get_content_price` --- get content price
    - `set_content_price` --- set content price
    - `increment_balance` --- increment user balance (temporary solution. It will be done in other module)
    - `make_offer_from_buyer_to_seller` --- make offer to buy content from buyer to seller
    - `accept_offer_from_buyer` --- content owner can accept offer to buy content from buyer
    - `reject_offer_from_owner` --- content owner can reject offer to buy content from buyer
    - `reject_offer_from_buyer` --- buyer can reject his offer to buy content
    - `news` --- get new about offer that user receive
    - `get_all_content` --- get all content in the whole system
- `cookies/account.json` --- contain user data (email, phone number and device id)
- `cookies/cookies.json` --- save hash and cid of stored content in PMES
- `cookies/generated.json` --- set of public and private keys. Used for choosing default value for changing owner, selling content, etc.
- `cookies/keys.json` --- contain user public and private keys

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

For running application run `python3` and initialize `PMESClient`. By default host is "http://127.0.0.1:8000".

```bash
from client import PMESClient
c = PMESClient()
```

Check commands present in this client:

```bash
c.help()
```

View all content descriptions:

```bash
c.get_all_content()
```

For posting your content to blockchain and sell it to other users create user account.

### Create user account

Firstly, generate public and private keys and fill account information such as email, device identificator and phone number:

```bash
c.gen_keys()
c.fill_form()
```

Secondly, create user account:

```bash
c.create_account()
```

Then, replenish the balance. Without money at your account you won't post a content.

```bash
c.increment_balance()
```

Check your balance:

```bash
c.get_account_data()
```

### Post data to blockchain

Now you can post data with description and price to blockchain.

Be careful the **blockchain keeps your data forever and you won't have an opportunity to delete or change them**.

```bash
c.post_data_to_blockchain()
```

For setting description or doing another staff get content identifier (cid). Data is posting to the blockchain via transaction.

When transaction will be approved (around 5-10 minutes) cid can be received by next command:

```bash
c.get_data_from_blockchain()
```

So, now you and other clients could see your content after executing command:

```bash
c.get_all_content()
```

### Buy someone's content

For buying someone's content run next command providing cid of the content:

```bash
c.make_offer_from_buyer_to_seller()
```

When the seller makes a decision to accept or reject your offer you will be informed by email.

If you change your mind about making an offer you could reject it:

```bash

c.reject_offer_from_buyer()
```

### Accept or reject buyer's offers

If someone makes you offer to buy your content you'll be informed by email.

Also, you could check this by running next command:

```bash
c.news()
```

For accepting or rejecting offer use corresponding command: 

```bash
c.accept_offer_from_buyer()

or

c.reject_offer_from_owner()
```
