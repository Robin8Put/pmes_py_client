# Robin8 BlockChain Mock of the Python client

This client allows to work with Profile Data Management System (PDMS):

- create client object
	- registration
	- authorization
- then you can:
	- save data in blockchain
	- get data from blockchain
	- get data owner wallet address
	- set/get data description

## Installation

Clone sources from git:

```bash
git clone https://github.com/Robin8Put/pdms_py_client.git
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