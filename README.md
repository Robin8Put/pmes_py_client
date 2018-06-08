# Mock of the Python client for PMES

This client allows to work with [Profile Management EcoSystem (PMES)](https://github.com/Robin8Put/pmes):

- set content in the blockchain
- get content from the blockchain
- buy and sell content
- accept or reject propositions to sell content
- view all content for the user or in the whole PMES

- `PMESClient` --- client module
    - `__init__` --- init class with server host
    - `help` --- show all commands of the python client
    - `gen_keys` --- generate public / private keys and write them to the `keys.json`
    - `fill_form` --- fill information about user such as email, phone number and device id
    - `create_account` --- create new user account
    - `get_account_data` --- get account details about user account
    - `get_data_from_blockchain` --- get content details from the blockchain by content identifier (`cid`)
    - `post_data_to_blockchain` --- write content to the blockchain
    - `set_content_description` --- set content description (in progress)
    - `set_content_price` --- set content price (in progress)
    - `increment_balance` --- increment user balance (temporary solution. It will be done in other maner)
    - `make_offer_from_buyer_to_seller` --- make offer to buy content from the current user to seller
    - `make_offer_from_buyer_to_seller_with_price` --- make offer to buy content with proposed price from the current user to seller
    - `accept_offer_from_buyer` --- content owner can accept offer to buy content from buyer
    - `reject_offer_from_owner` --- content owner can reject offer to buy content from buyer
    - `reject_offer_from_buyer` --- buyer can reject his offer to buy content
    - `news` --- get the list of all news about offers that user received to sell his content
    - `get_all_content` --- get all content in the whole PMES
    - `get_all_content_which_post_user` --- get all content which belongs to the user (if user sell rights to content it won't be displayed here)
    - `get_all_offers_which_made_user` --- get all active offers which made the user (if an offer will be finished with accepting or reject it won't be displayed here)
    - `get_all_offers_received_for_content_by_cid` --- get all active offers for some content identifier
- `cookies/account.json` --- contain user's data (email, phone number and device id)
- `cookies/cookies.json` --- save hash and cid of stored content in PMES
- `cookies/generated.json` --- set of public and private keys. Used for choosing default value for changing owner, selling content, etc.
- `cookies/keys.json` --- contain user public and private keys

`amount`, `balance`, `offer_price`, `price`, `buyer_price` and `seller_price` represented as `x * 10^8`. Where `x` could be `float`.

For checking status of transaction in the QTUM blockchain you could use the site https://testnet.qtum.org.
When the status of transaction changes from `Unconfirmed` to `Success` this means that your data was written to the blockchain.

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
c.get_all_content_which_post_user()
```

For viewing details about content you could use following command:

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

You could makes offer by specifying your price:

```bash
c.make_offer_from_buyer_to_seller_with_price()
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

### View own information

For checking all content, that you post use:

```bash
c.get_all_content_which_post_user()
```

For checking all offers, that you made use:

```bash
c.get_all_offers_which_made_user()
```

For checking all offers, that other users made for your contents use:

```bash
c.get_all_offers_received_for_content_by_cid()
```
