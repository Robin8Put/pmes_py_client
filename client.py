import os
import hmac
import hashlib
import ecdsa
import struct
import codecs
import json
import random
from ecdsa.curves import SECP256k1
from ecdsa.ecdsa import int_to_string, string_to_int
from ecdsa.numbertheory import square_root_mod_prime as sqrt_mod
import time
import datetime
import requests
import codecs
import hashlib
from hashlib import sha256
from ecdsa import SigningKey, VerifyingKey
import ecdsa
import logging
from jsonrpcclient.http_client import HTTPClient

decode_hex = codecs.getdecoder("hex_codec")
encode_hex = codecs.getencoder("hex_codec")


__base58_alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
__base58_alphabet_bytes = b'123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
__base58_radix = len(__base58_alphabet)


def get_time_stamp():
        ts = time.time()
        return datetime.datetime.fromtimestamp(ts).strftime('%Y%m%d%H%M')


def __string_to_int(data):
    "Convert string of bytes Python integer, MSB"
    val = 0
   
    # Python 2.x compatibility
    if type(data) == str:
        data = bytearray(data)

    for (i, c) in enumerate(data[::-1]):
        val += (256**i)*c
    return val


def encode(data):
    "Encode bytes into Bitcoin base58 string"
    enc = ''
    val = __string_to_int(data)
    while val >= __base58_radix:
        val, mod = divmod(val, __base58_radix)
        enc = __base58_alphabet[mod] + enc
    if val:
        enc = __base58_alphabet[val] + enc

    # Pad for leading zeroes
    n = len(data)-len(data.lstrip(b'\0'))
    return __base58_alphabet[0]*n + enc


def check_encode(raw):
    "Encode raw bytes into Bitcoin base58 string with checksum"
    chk = sha256(sha256(raw).digest()).digest()[:4]
    return encode(raw+chk)


def decode(data):
    "Decode Bitcoin base58 format string to bytes"
    # Python 2.x compatability
    if bytes != str:
        data = bytes(data, 'ascii')

    val = 0
    for (i, c) in enumerate(data[::-1]):
        val += __base58_alphabet_bytes.find(c) * (__base58_radix**i)

    dec = bytearray()
    while val >= 256:
        val, mod = divmod(val, 256)
        dec.append(mod)
    if val:
        dec.append(val)

    return bytes(dec[::-1])


def check_decode(enc):
    "Decode bytes from Bitcoin base58 string and test checksum"
    dec = decode(enc)
    raw, chk = dec[:-4], dec[-4:]
    if chk != sha256(sha256(raw).digest()).digest()[:4]:
        raise ValueError("base58 decoding checksum error")
    else:
        return raw




MIN_ENTROPY_LEN = 128        # bits
BIP32_HARDEN    = 0x80000000 # choose from hardened set of child keys
CURVE_GEN       = ecdsa.ecdsa.generator_secp256k1
CURVE_ORDER     = CURVE_GEN.order()
FIELD_ORDER     = SECP256k1.curve.p()
INFINITY        = ecdsa.ellipticcurve.INFINITY
EX_MAIN_PRIVATE = codecs.decode('0488ade4', 'hex') # Version string for mainnet extended private keys
EX_MAIN_PUBLIC  = codecs.decode('0488b21e', 'hex') # Version string for mainnet extended public keys
EX_TEST_PRIVATE = codecs.decode('04358394', 'hex') # Version string for testnet extended private keys
EX_TEST_PUBLIC  = codecs.decode('043587CF', 'hex') # Version string for testnet extended public keys

class BIP32Key(object):

    # Static initializers to create from entropy or external formats
    #
    @staticmethod
    def fromEntropy(entropy, public=False, testnet=False):
        "Create a BIP32Key using supplied entropy >= MIN_ENTROPY_LEN"
        if entropy == None:
            entropy = os.urandom(MIN_ENTROPY_LEN/8) # Python doesn't have os.random()
        if not len(entropy) >= MIN_ENTROPY_LEN/8:
            raise ValueError("Initial entropy %i must be at least %i bits" %
                                (len(entropy), MIN_ENTROPY_LEN))
        I = hmac.new(b"Bitcoin seed", entropy, hashlib.sha512).digest()
        Il, Ir = I[:32], I[32:]
        # FIXME test Il for 0 or less than SECP256k1 prime field order
        key = BIP32Key(secret=Il, chain=Ir, depth=0, index=0, fpr=b'\0\0\0\0', public=False, testnet=testnet)
        if public:
            key.SetPublic()
        return key

    @staticmethod
    def fromExtendedKey(xkey, public=False):
        """
        Create a BIP32Key by importing from extended private or public key string

        If public is True, return a public-only key regardless of input type.
        """
        # Sanity checks
        raw = Base58.check_decode(xkey)
        if len(raw) != 78:
            raise ValueError("extended key format wrong length")

        # Verify address version/type
        version = raw[:4]
        if version == EX_MAIN_PRIVATE:
            is_testnet = False
            is_pubkey = False
        elif version == EX_TEST_PRIVATE:
            is_testnet = True
            is_pubkey = False
        elif version == EX_MAIN_PUBLIC:
            is_testnet = False
            is_pubkey = True
        elif version == EX_TEST_PUBLIC:
            is_testnet = True
            is_pubkey = True
        else:
            raise ValueError("unknown extended key version")

        # Extract remaining fields
        # Python 2.x compatibility
        if type(raw[4]) == int:
            depth = raw[4]
        else:
            depth = ord(raw[4])
        fpr = raw[5:9]
        child = struct.unpack(">L", raw[9:13])[0]
        chain = raw[13:45]
        secret = raw[45:78]

        # Extract private key or public key point
        if not is_pubkey:
            secret = secret[1:]
        else:
            # Recover public curve point from compressed key
            # Python3 FIX
            lsb = secret[0] & 1 if type(secret[0]) == int else ord(secret[0]) & 1
            x = string_to_int(secret[1:])
            ys = (x**3+7) % FIELD_ORDER # y^2 = x^3 + 7 mod p
            y = sqrt_mod(ys, FIELD_ORDER)
            if y & 1 != lsb:
                y = FIELD_ORDER-y
            point = ecdsa.ellipticcurve.Point(SECP256k1.curve, x, y)
            secret = ecdsa.VerifyingKey.from_public_point(point, curve=SECP256k1)

        key = BIP32Key(secret=secret, chain=chain, depth=depth, index=child, fpr=fpr, public=is_pubkey, testnet=is_testnet)
        if not is_pubkey and public:
            key = key.SetPublic()
        return key


    # Normal class initializer
    def __init__(self, secret, chain, depth, index, fpr, public=False, testnet=False):
        """
        Create a public or private BIP32Key using key material and chain code.

        secret   This is the source material to generate the keypair, either a
                 32-byte string representation of a private key, or the ECDSA
                 library object representing a public key.

        chain    This is a 32-byte string representation of the chain code

        depth    Child depth; parent increments its own by one when assigning this

        index    Child index

        fpr      Parent fingerprint

        public   If true, this keypair will only contain a public key and can only create
                 a public key chain.
        """

        self.public = public
        if public is False:
            self.k = ecdsa.SigningKey.from_string(secret, curve=SECP256k1)
            self.K = self.k.get_verifying_key()
        else:
            self.k = None
            self.K = secret

        self.C = chain
        self.depth = depth
        self.index = index
        self.parent_fpr = fpr
        self.testnet = testnet


    # Internal methods not intended to be called externally
    #
    def hmac(self, data):
        """
        Calculate the HMAC-SHA512 of input data using the chain code as key.

        Returns a tuple of the left and right halves of the HMAC
        """         
        I = hmac.new(self.C, data, hashlib.sha512).digest()
        return (I[:32], I[32:])


    def CKDpriv(self, i):
        """
        Create a child key of index 'i'.

        If the most significant bit of 'i' is set, then select from the
        hardened key set, otherwise, select a regular child key.

        Returns a BIP32Key constructed with the child key parameters,
        or None if i index would result in an invalid key.
        """
        # Index as bytes, BE
        i_str = struct.pack(">L", i)

        # Data to HMAC
        if i & BIP32_HARDEN:
            data = b'\0' + self.k.to_string() + i_str
        else:
            data = self.PublicKey() + i_str
        # Get HMAC of data
        (Il, Ir) = self.hmac(data)

        # Construct new key material from Il and current private key
        Il_int = string_to_int(Il)
        if Il_int > CURVE_ORDER:
            return None
        pvt_int = string_to_int(self.k.to_string())
        k_int = (Il_int + pvt_int) % CURVE_ORDER
        if (k_int == 0):
            return None
        secret = (b'\0'*32 + int_to_string(k_int))[-32:]
        
        # Construct and return a new BIP32Key
        return BIP32Key(secret=secret, chain=Ir, depth=self.depth+1, index=i, fpr=self.Fingerprint(), public=False, testnet=self.testnet)


    def CKDpub(self, i):
        """
        Create a publicly derived child key of index 'i'.

        If the most significant bit of 'i' is set, this is
        an error.

        Returns a BIP32Key constructed with the child key parameters,
        or None if index would result in invalid key.
        """

        if i & BIP32_HARDEN:
            raise Exception("Cannot create a hardened child key using public child derivation")

        # Data to HMAC.  Same as CKDpriv() for public child key.
        data = self.PublicKey() + struct.pack(">L", i)

        # Get HMAC of data
        (Il, Ir) = self.hmac(data)

        # Construct curve point Il*G+K
        Il_int = string_to_int(Il)
        if Il_int >= CURVE_ORDER:
            return None
        point = Il_int*CURVE_GEN + self.K.pubkey.point
        if point == INFINITY:
            return None

        # Retrieve public key based on curve point
        K_i = ecdsa.VerifyingKey.from_public_point(point, curve=SECP256k1)

        # Construct and return a new BIP32Key
        return BIP32Key(secret=K_i, chain=Ir, depth=self.depth+1, index=i, fpr=self.Fingerprint(), public=True, testnet=self.testnet)


    # Public methods
    #
    def ChildKey(self, i):
        """
        Create and return a child key of this one at index 'i'.

        The index 'i' should be summed with BIP32_HARDEN to indicate
        to use the private derivation algorithm.
        """
        if self.public is False:
            return self.CKDpriv(i)
        else:
            return self.CKDpub(i)


    def SetPublic(self):
        "Convert a private BIP32Key into a public one"
        self.k = None
        self.public = True


    def PrivateKey(self):
        "Return private key as string"
        if self.public:
            raise Exception("Publicly derived deterministic keys have no private half")
        else:
            return self.k.to_string()


    def PublicKey(self):
        "Return compressed public key encoding"
        padx = (b'\0'*32 + int_to_string(self.K.pubkey.point.x()))[-32:]
        if self.K.pubkey.point.y() & 1:
            ck = b'\3'+padx
        else:
            ck = b'\2'+padx
        return ck


    def ChainCode(self):
        "Return chain code as string"
        return self.C


    def Identifier(self):
        "Return key identifier as string"
        cK = self.PublicKey()
        return hashlib.new('ripemd160', sha256(cK).digest()).digest()


    def Fingerprint(self):
        "Return key fingerprint as string"
        return self.Identifier()[:4]


    def Address(self):
        "Return compressed public key address"
        addressversion = b'\x00' if not self.testnet else b'\x6f'
        vh160 = addressversion + self.Identifier()
        return Base58.check_encode(vh160)


    def WalletImportFormat(self):
        "Returns private key encoded for wallet import"
        if self.public:
            raise Exception("Publicly derived deterministic keys have no private half")
        addressversion = b'\x80' if not self.testnet else b'\xef'
        raw = addressversion + self.k.to_string() + b'\x01' # Always compressed
        return Base58.check_encode(raw)


    def ExtendedKey(self, private=True, encoded=True):
        "Return extended private or public key as string, optionally Base58 encoded"
        if self.public is True and private is True:
            raise Exception("Cannot export an extended private key from a public-only deterministic key")
        if not self.testnet:
            version = EX_MAIN_PRIVATE if private else EX_MAIN_PUBLIC
        else:
            version = EX_TEST_PRIVATE if private else EX_TEST_PUBLIC
        depth = bytes(bytearray([self.depth]))
        fpr = self.parent_fpr
        child = struct.pack('>L', self.index)
        chain = self.C
        if self.public is True or private is False:
            data = self.PublicKey()
        else:
            data = b'\x00' + self.PrivateKey()
        raw = version+depth+fpr+child+chain+data
        if not encoded:
            return raw
        else:
            return Base58.check_encode(raw)

    # Debugging methods
    #
    def dump(self):
        "Dump key fields mimicking the BIP0032 test vector format"
        print("   * Identifier")
        print("     * (hex):      ", self.Identifier().encode('hex'))
        print("     * (fpr):      ", self.Fingerprint().encode('hex'))
        print("     * (main addr):", self.Address())
        if self.public is False:
            print("   * Secret key")
            print("     * (hex):      ", self.PrivateKey().encode('hex'))
            print("     * (wif):      ", self.WalletImportFormat())
        print("   * Public key")
        print("     * (hex):      ", self.PublicKey().encode('hex'))
        print("   * Chain code")
        print("     * (hex):      ", self.C.encode('hex'))
        print("   * Serialized")
        print("     * (pub hex):  ", self.ExtendedKey(private=False, encoded=False).encode('hex'))
        print("     * (prv hex):  ", self.ExtendedKey(private=True, encoded=False).encode('hex'))
        print("     * (pub b58):  ", self.ExtendedKey(private=False, encoded=True))
        print("     * (prv b58):  ", self.ExtendedKey(private=True, encoded=True))


class Bip32Keys:

    def __init__(self, init_params):
        if isinstance(init_params, str):
            self.init_from_entropy(init_params)
        elif isinstance(init_params, dict):
            if 'entropy' in init_params:
                self.init_from_entropy(init_params['entropy'])
            elif 'private_key' in init_params:
                self.init_from_private_key(init_params['private_key'])
            else:
                raise NotImplementedError()


    def init_from_entropy(self, entropy):
        entropy = entropy.encode()

        key = BIP32Key.fromEntropy(entropy, public=False)
        self.private_key = key.PrivateKey()
        self.public_key = key.PublicKey()

        self.uncompressed_public_key = decode_hex(Bip32Keys.to_uncompressed_public_key(
            self.get_public_key()
        ))[0]


    def init_from_private_key(self, private_key):
        sk = SigningKey.from_string(string=decode_hex(private_key)[0], curve=ecdsa.SECP256k1, hashfunc=sha256)
        vk = sk.get_verifying_key()

        self.private_key = sk.to_string()
        self.public_key = decode_hex(Bip32Keys.to_compressed_public_key(encode_hex(vk.to_string())[0].decode()))[0]
        self.uncompressed_public_key = b'\x04' + vk.to_string()

    def get_public_key(self):
        return encode_hex(self.public_key)[0].decode()

    def get_private_key(self):
        return encode_hex(self.private_key)[0].decode()

    def get_uncompressed_public_key(self):
        return encode_hex(self.uncompressed_public_key)[0].decode()

    def sign_msg(self, message):
        return Bip32Keys.sign_message(message, self.get_private_key())

    def verify_msg(self, message, signature):
        return Bip32Keys.verify_message(message, signature, self.get_uncompressed_public_key())

    @staticmethod
    def to_uncompressed_public_key(public_key):
        p_hex = 'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F'
        p = int(p_hex, 16)

        x_hex = public_key[2:66]
        x = int(x_hex, 16)
        prefix = public_key[0:2]

        y_square = (pow(x, 3, p) + 7) % p
        y_square_square_root = pow(y_square, (p + 1) // 4, p)
        if (prefix == "02" and y_square_square_root & 1) or (prefix == "03" and not y_square_square_root & 1):
            y = (-y_square_square_root) % p
        else:
            y = y_square_square_root

        computed_y_hex = format(y, '064x')
        computed_uncompressed_key = "04" + x_hex + computed_y_hex

        return computed_uncompressed_key

    @staticmethod
    def to_compressed_public_key(public_key):
        if len(public_key) == 66:
            return public_key

        y_hex = public_key[64:]
        if int(y_hex, 16) & 1:
            prefix = '03'
        else:
            prefix = '02'

        if len(public_key) == 130:
            return prefix + public_key[2:66]
        elif len(public_key) == 128:
            return prefix + public_key[:64]

    @staticmethod
    def sign_message(message, private_key):
        priv_key = Bip32Keys._validate_private_key_for_signature(private_key)
        message = message.encode()
        sk = SigningKey.from_string(curve=ecdsa.SECP256k1, string=decode_hex(priv_key)[0], hashfunc=sha256)
        sig = sk.sign(message)
        return encode_hex(sig)[0].decode()

    @staticmethod
    def verify_message(message, signature, public_key):
        pub_key = Bip32Keys._validate_public_key_for_signature(public_key)
        sig = Bip32Keys._validate_signature(signature)
        msg = message.encode()
        vk = VerifyingKey.from_string(string=decode_hex(pub_key)[0], curve=ecdsa.SECP256k1, hashfunc=sha256)

        try:
            vk.verify(decode_hex(sig)[0], msg)
        except:
            return False
        return True

    @staticmethod
    def _validate_private_key_for_signature(private_key):
        if len(private_key) == 64:
            return private_key
        elif len(private_key) == 66:
            if private_key[0:2] == '80':
                return private_key[2:]
            elif private_key[-2:] == '01':
                return private_key[:-2]
        elif len(private_key) == 68:
            return private_key[2:-2]
        else:
            raise Exception('Bad private key length')

    @staticmethod
    def _validate_public_key_for_signature(public_key):
        if len(public_key) == 128:
            return public_key
        elif len(public_key) == 130:
            return public_key[2:]
        elif len(public_key) == 66:
            return Bip32Keys.to_uncompressed_public_key(public_key)[2:]
        else:
            raise Exception('Unsupported public key format')

    @staticmethod
    def _validate_signature(signature):
        if len(signature) == 128:
            return signature
        elif len(signature) == 140:
            return signature[8:72] + signature[-64:]
        else:
            raise Exception('Unsupported signature format')


class Cookies:
    class Type:
        account = "cookies/account.json"
        cookies = "cookies/cookies.json"
        keys = "cookies/keys.json"

    @classmethod
    def get(cls, cookie_type):
        with open(cookie_type) as accountfile:
            account = json.load(accountfile)
        return account

    @classmethod
    def set(cls, cookie_type, data):
        with open(cookie_type, "w+") as accountfile:
            accountfile.write(json.dumps(data))

    @classmethod
    def clear(cls, cookie_type):
        Cookies.set(cookie_type, {})

    @classmethod
    def clear_all(cls):
        Cookies.set(Cookies.Type.account, {})
        Cookies.set(Cookies.Type.cookies, {})
        Cookies.set(Cookies.Type.keys, {})

class PMESClient(object):
    def __init__(self, host="http://127.0.0.1:8000"):
        #self.host = "http://176.31.125.26:8000"
        #self.host = "http://127.0.0.1:8000"
        self.host = host

        # Cookies.clear_all()

    @classmethod
    def _get_time_stamp(cls):
        ts = time.time()
        return datetime.datetime.fromtimestamp(ts).strftime('%Y%m%d%H%M')

    def gen_keys(self):
        with open("cookies/generated.json") as generated:
            keys = random.choice(json.load(generated))
        Cookies.set(Cookies.Type.keys, keys)
        print("Generating keys...")
        time.sleep(2)
        print("Public and private keys saved at 'cookies/keys.json' file.")

    def _input_variable(self, message, default=None):
        while True:
            var = input(message) or default
            if var:
                break
        return var

    def fill_form(self):
        email = self._input_variable("* Insert your e-mail: ")
        device_id = self._input_variable("* Insert your device id: ")
        phone = input("Insert your phone (optional): ")

        data = {"email":email, "device_id":device_id}
        if phone:
            data.update({"phone":phone})

        Cookies.set(Cookies.Type.account, data)
        print("Account data submited.")

    def _is_response_json(self, request):
        try:
            return request.json()
        except:
            print(request.text)
            return None

    def help(self):
        print("===   Profile Management EcoSystem client (PMES client)   ===")
        print("Commands:")
        print(" - gen_keys")
        print(" - fill_form")
        print(" - create_account")
        print(" - get_account_data")
        print(" - get_data_from_blockchain")
        print(" - post_data_to_blockchain")
        print(" - get_content_description")
        print(" - set_content_description")
        print(" - get_content_price")
        print(" - set_content_price")
        print(" - increment_balance")
        print(" - make_offer_from_buyer_to_seller")
        print(" - accept_offer_from_buyer")
        print(" - reject_offer_from_buyer")
        print(" - reject_offer_from_owner")
        print(" - news")
        print(" - get_all_content")

    def create_account(self):
        Cookies.clear(Cookies.Type.cookies)

        endpoint = "/api/accounts"
        url = "%s%s" % (self.host, endpoint)

        keys = Cookies.get(Cookies.Type.keys)
        account = Cookies.get(Cookies.Type.account)
        message = {
                "timestamp":PMESClient._get_time_stamp(),
                "email":account["email"],
                "device_id":account["device_id"]
            }
        if account["phone"]:
            message["phone"] = account["phone"]
        message = json.dumps(message)
        data = {
            "public_key": keys["public_key"],
            "message": message,
            "signature": Bip32Keys.sign_message(message, 
                            keys["private_key"])
        }

        time.sleep(2)
        request = requests.post(url, data=data)
        return self._is_response_json(request)

    def get_account_data(self):
        keys = Cookies.get(Cookies.Type.keys)
        endpoint = "/api/accounts/%s" % keys["public_key"]
        url = "%s%s" % (self.host, endpoint)

        message = json.dumps({"timestamp": PMESClient._get_time_stamp(), "public_key": keys["public_key"]})
        params = {
            "public_key": keys["public_key"],
            "message": message,
            "signature": Bip32Keys.sign_message(message, 
                            keys["private_key"])
        }

        time.sleep(2)
        request = requests.get(url, params=params)
        return self._is_response_json(request)

    def get_data_from_blockchain(self):
        keys = Cookies.get(Cookies.Type.keys)
        endpoint = "/api/blockchain/%s/content" % keys["public_key"]
        url = "%s%s" % (self.host, endpoint)

        cookies = Cookies.get(Cookies.Type.cookies)

        print("One of the parameters (hash or CID) is required")
        _hash = input("Hash: ")
        cid = input("cid: ")
        if not _hash and not cid:
            print("Read hash and cid from cookies")
            _hash = cookies.get("hash", None)
            if not _hash:
                cid = cookies.get("cid", None)

        if not (_hash or cid):
            print("Hash and cid are empty")
            return

        account = Cookies.get(Cookies.Type.account)
        message = account.copy()
        message["timestamp"] = PMESClient._get_time_stamp(),
        message = json.dumps(message)
        params = {}
        if _hash:
            params["hash"] = _hash
        if cid:
            params["cid"] = cid

        time.sleep(2)
        request = requests.get(url, params=params)
        res = self._is_response_json(request)        
        if res:
            if "error" in res.keys():
                if res["error"] == "Hash not found":
                    print("Content is writing to the blockchain. Try to repeat request latter, please")
                else:
                    print(res)
                return

            if _hash:
                cookies["hash"] = _hash

                if res["cid"] and isinstance(res["cid"], str) or isinstance(res["cid"], int):
                    cookies["cid"] = res["cid"]
                else:
                    cookies["cid"] = None
            if cid:
                cookies["hash"] = None
                cookies["cid"] = cid

            Cookies.set(Cookies.Type.cookies, cookies)

            return res

    def post_data_to_blockchain(self):
        keys = Cookies.get(Cookies.Type.keys)
        endpoint = "/api/blockchain/%s/content" % keys["public_key"]
        url = "%s%s" % (self.host, endpoint)

        cus = self._input_variable("* Content (default 'My favorite data'): ", "My favorite data")
        price = self._input_variable("* Price (default 10): ", 10)
        description = self._input_variable("* Description (default 'description'): ", "description")

        message = json.dumps({
                "timestamp": PMESClient._get_time_stamp(),
                "cus":cus,
                "price": price,
                "description": description
            })
        data = {
            "public_key": keys["public_key"],
            "message": message,
            "signature": Bip32Keys.sign_message(message, 
                            keys["private_key"])
        }
        
        time.sleep(2)
        request = requests.post(url, data=data)
        res = self._is_response_json(request)
        if res:
            if "error" in res.keys():
                print(res)
                return

            print("Hash = %s" % res["hash"])

            _hash = None
            if "hash" in res.keys():
                _hash = res["hash"]

            cookies = Cookies.get(Cookies.Type.cookies)
            cookies["hash"] = _hash
            cookies["cid"] = None
            Cookies.set(Cookies.Type.cookies, cookies)

    def get_content_description(self):
        cookies = Cookies.get(Cookies.Type.cookies)
        endpoint = "/api/blockchain/%s/description" % cookies["cid"]

        cid = self._input_variable("* CID (default from cookies): ", cookies.get("cid", None))

        params = {"cid":cid}
        url = "%s%s" % (self.host, endpoint)
        request = requests.get(url, params=params)
        return self._is_response_json(request)

    def set_content_description(self):
        cookies = Cookies.get(Cookies.Type.cookies)
        endpoint = "/api/blockchain/%s/description" % cookies["cid"]
        description = input("Insert description ('my description' by default): ") or "my description"

        cid = self._input_variable("* CID (default from cookies): ", cookies.get("cid", None))

        keys = Cookies.get(Cookies.Type.keys)   
        message = json.dumps({
                "timestamp":PMESClient._get_time_stamp(),
                "cid":cid,
                "description": description,
            })
        data = {
            "public_key": keys["public_key"],
            "message": message,
            "signature": Bip32Keys.sign_message(message, 
                            keys["private_key"])
        }

        url = "%s%s" % (self.host, endpoint)
        request = requests.post(url, data=data)
        return self._is_response_json(request)

    def get_content_price(self):
        cookies = Cookies.get(Cookies.Type.cookies)
        endpoint = "/api/blockchain/%s/price" % cookies["cid"]

        cid = self._input_variable("* CID (default from cookies): ", cookies.get("cid", None))

        params = {"cid":cid}
        url = "%s%s" % (self.host, endpoint)
        request = requests.get(url, params=params)
        return self._is_response_json(request)

    # Check that it return "price"
    def set_content_price(self):
        cookies = Cookies.get(Cookies.Type.cookies)
        endpoint = "/api/blockchain/%s/price" % cookies["cid"]
        price = input("Insert price (100 by default): ") or 100

        cid = self._input_variable("* CID (default from cookies): ", cookies.get("cid", None))

        keys = Cookies.get(Cookies.Type.keys)   
        message = json.dumps({
                "timestamp":PMESClient._get_time_stamp(),
                "cid":cid,
                "price": price,
            })
        data = {
            "public_key": keys["public_key"],
            "message": message,
            "signature": Bip32Keys.sign_message(message, 
                            keys["private_key"])
        }

        url = "%s%s" % (self.host, endpoint)
        request = requests.post(url, data=data)
        if self._is_response_json(request):
            print("\nYour price is: " + str(request.json()["price"]))

    def make_offer_from_buyer_to_seller(self):
        cookies = Cookies.get(Cookies.Type.cookies)
        cid = self._input_variable("* CID (default from cookies): ", cookies.get("cid", None))

        keys = Cookies.get(Cookies.Type.keys)   
        message = json.dumps({
                "timestamp":PMESClient._get_time_stamp(),
                "cid":cid,
                "buyer_access_string": keys["public_key"],
            })
        data = {
            "public_key": keys["public_key"],
            "message": message,
            "signature": Bip32Keys.sign_message(message, 
                            keys["private_key"])
        }

        endpoint = "/api/blockchain/%s/offer" % keys["public_key"]
        url = "%s%s" % (self.host, endpoint)
        request = requests.post(url, data=data)
        return self._is_response_json(request)

    def accept_offer_from_buyer(self):
        cookies = Cookies.get(Cookies.Type.cookies)
        cid = self._input_variable("* CID (default from cookies): ", cookies.get("cid", None))
        buyer_pubkey = self._input_variable("* Buyer public key: ")

        keys = Cookies.get(Cookies.Type.keys)   
        message = json.dumps({
                "timestamp":PMESClient._get_time_stamp(),
                "cid":cid,
                "buyer_access_string": keys["public_key"],
                "buyer_pubkey": buyer_pubkey
            })
        data = {
            "public_key": keys["public_key"],
            "message": message,
            "signature": Bip32Keys.sign_message(message, 
                            keys["private_key"])
        }

        endpoint = "/api/blockchain/%s/deal" % keys["public_key"]
        url = "%s%s" % (self.host, endpoint)
        request = requests.post(url, data=data)
        return self._is_response_json(request)

    def reject_offer_from_buyer(self):
        cookies = Cookies.get(Cookies.Type.cookies)
        cid = self._input_variable("* CID (default from cookies): ", cookies.get("cid", None))
        buyer_addr = self._input_variable("* Your address: ")

        keys = Cookies.get(Cookies.Type.keys)
        message = json.dumps({
                "timestamp":PMESClient._get_time_stamp(),
                "offer_id":{
                    "cid":cid,
                    "buyer_addr": buyer_addr
                }
            })
        data = {
            "public_key": keys["public_key"],
            "message": message,
            "signature": Bip32Keys.sign_message(message,
                            keys["private_key"])
        }

        endpoint = "/api/blockchain/%s/offer" % keys["public_key"]
        url = "%s%s" % (self.host, endpoint)
        request = requests.put(url, data=data)
        return self._is_response_json(request)

    def reject_offer_from_owner(self):
        cookies = Cookies.get(Cookies.Type.cookies)
        cid = self._input_variable("* CID (default from cookies): ", cookies.get("cid", None))
        buyer_addr = self._input_variable("* Buyer address: ")

        keys = Cookies.get(Cookies.Type.keys)
        message = json.dumps({
                "timestamp":PMESClient._get_time_stamp(),
                "offer_id":{
                    "cid":cid,
                    "buyer_addr": buyer_addr
                }
            })
        data = {
            "public_key": keys["public_key"],
            "message": message,
            "signature": Bip32Keys.sign_message(message,
                            keys["private_key"])
        }

        endpoint = "/api/blockchain/%s/offer" % keys["public_key"]
        url = "%s%s" % (self.host, endpoint)
        request = requests.put(url, data=data)
        return self._is_response_json(request)

    # Delete function when it becomes unnecessary
    def increment_balance(self):
        amount = self._input_variable("* Amount (default 100): ", 100)

        account = self.get_account_data()
        if not account:
            print("Error with account")
            return
        uid = account["id"]

        print("\n[+] -- Refilling buyers balance")
        time.sleep(1)
        port = "8004"
        endpoint = "/api/balance"
        host = self.host.split(':')
        url = "%s:%s:%s%s" % (host[0], host[1], port, endpoint)
        client = HTTPClient(url)
        client.request(method_name="incbalance", uid=uid, amount=amount)
        response = client.request(method_name="getbalance", uid=uid)
        print("\nBuyers balance is: " + str(response[str(uid)]))

    def news(self):
        keys = Cookies.get(Cookies.Type.keys)
        message = json.dumps({
                "timestamp":PMESClient._get_time_stamp()
            })
        data = {
            "public_key": keys["public_key"],
            "message": message,
            "signature": Bip32Keys.sign_message(message, 
                            keys["private_key"])
        }

        endpoint = "/api/accounts/%s/news" % keys["public_key"]
        url = "%s%s" % (self.host, endpoint)
        request = requests.get(url, data=data)
        return self._is_response_json(request)

    def get_all_content(self):
        endpoint = "/api/blockchain/content"
        url = "%s%s" % (self.host, endpoint)
        request = requests.get(url)
        res = self._is_response_json(request)
        if res:
            print("=======================   Content   =======================")
            print("Found {} items\n".format(len(res)))
            for content in res:
                print("Description: {}".format(content["description"]))
                print("Owner: {}".format(content["owneraddr"]))
                print("Price: {}".format(content["price"]))
                print("cid: {}".format(content["cid"]))
                print()
        else:
            print(res)
