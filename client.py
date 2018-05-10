import requests
from random import *
import string
from qtum_utils.qtum import Qtum
import datetime
import time
import codecs
from AESCipher import AESCipher


class Client:
    domen = 'http://192.168.1.199:8000'
    url = '/api/accounts'
    api_root = '/api'

    @staticmethod
    def generate_token(length=16, chars=string.ascii_letters + string.punctuation + string.digits):
        return "".join(choice(chars) for x in range(0, length))

    def __init__(self, qtum=None, mainnet=False):
        if qtum is None:
            self.q = Qtum('hfjkdsfjadsfjdsaofellohellohjfskljdsfcds', mainnet)
        else:
            self.q = qtum
        self.public_key = self.q.get_uncompressed_public_key()
        self.private_key = self.q.get_private_key()
        self.qtum_address = self.q.get_qtum_address()

        self.decode_hex = codecs.getdecoder("hex_codec")
        self.encode_hex = codecs.getencoder("hex_codec")

    def get_public_key(self):
        return self.public_key

    def get_private_key(self):
        return self.private_key

    def get_qtum_address(self):
        return self.qtum_address

    def get_time_stapm(self):
        ts = time.time()
        return datetime.datetime.fromtimestamp(ts).strftime('%Y%m%d%H%M')

    def create(self, device_id, email):
        message = "create"+self.get_time_stapm()
        self.device_id = device_id
        self.email = email
        print('post request: ', self.domen + self.url)
        print('public key: ', self.public_key)
        print('device_id: ', self.device_id)
        print('email: ', self.email)
        print('message: ', message)
        print('signature: ', Qtum.sign_message(message, self.private_key))
        r = requests.post(self.domen + self.url,
                          data={'public_key': self.public_key,
                                'device_id': self.device_id,
                                'email': self.email,
                                'message': message,
                                'signature': Qtum.sign_message(message, self.private_key)
                                })
        response = r.json()
        #print(response)
        self.uri = response['hyper']

        return response

    def auth(self):  # not used
        message = 'auth'+self.get_time_stapm()
        params = '/?message=%s&signature=%s' % (message, Qtum.sign_message(message, self.private_key))
        r = requests.get(self.domen + self.url + '/' + self.public_key + params)
        response = r.json()
        print(response)
        #if error return
        self.uri = response['hyper']
        self.device_id = response['account']['device_id']
        self.email = response['account']['email']

        return response

    def get_level(self):  # not used
        message = 'getLevel'+self.get_time_stapm()
        params = '/?message=%s&signature=%s' % (message, Qtum.sign_message(message, self.private_key))
        print(params)
        r = requests.get(self.domen + self.uri['level'] + params)
        response = r.json()
        return response

    def get_balance(self):  # not used
        message = 'getBalance' + self.get_time_stapm()
        params = '/?message=%s&signature=%s' % (message, Qtum.sign_message(message, self.private_key))
        print(params)
        r = requests.get(self.domen + self.uri['balance'] + params)
        response = r.json()
        return response

    def get_data_by_cid(self, cid):
        cid = int(cid)
        message = 'getData' + self.get_time_stapm()
        params = '/?message=%s&signature=%s&cid=%d' % (message, Qtum.sign_message(message, self.private_key), cid)
        print(self.domen + self.uri['account'] + params)
        r = requests.get(self.domen + self.uri['account'] + params)
        response = r.json()
        return response

    def get_data_by_hash(self, hash):
        message = 'getData' + self.get_time_stapm()
        params = '/?message=%s&signature=%s&hash=%s' % (message, Qtum.sign_message(message, self.private_key), hash)
        url = self.domen + self.uri['account'] + params
        print(url)
        r = requests.get(url)
        response = r.json()
        return response

    def get_account(self, private_key=None):
        if private_key is None:
            this_priv_key = self.private_key
        else:
            this_priv_key = private_key
        message = 'getAccount' + self.get_time_stapm()
        params = '/?message=%s&signature=%s' % (message, Qtum.sign_message(message, this_priv_key))
        url = self.domen + self.uri['account'] + params
        print(url)
        r = requests.get(url)
        response = r.json()
        return response

    def create_data(self, data):
        message = "createData" + data +self.get_time_stapm()
        url = self.domen + self.uri['account']
        print('post request: ' + self.domen + self.url)
        print('public key: ' + self.public_key)
        print('owneraddr: ' + self.qtum_address)
        print('data: ' + data)
        print('message: ' + message)
        print('signature: ' + Qtum.sign_message(message, self.private_key))
        print('url: ' + url)
        r = requests.post(url,
                          data={'public_key': self.public_key,
                                'message': message,
                                'signature': Qtum.sign_message(message, self.private_key),
                                'data': data,
                                'owneraddr': self.qtum_address
                                })
        response = r.json()
        #print(response)
        return response

    def upload_file(self, filename, password):
        hex_data = Client.file_to_hex(filename)
        print('hex_data: ', hex_data)
        encrypted_data = Client.encrypt_hex(hex_data, password)
        print('encrypted data: ', encrypted_data)

        response = self.create_data(encrypted_data)
        return response


    def download_file(self, filename, password, cid):
        cid = int(cid)
        encrypted_data = self.get_data_by_cid(cid)['data']
        print('encrypted data: ', encrypted_data)
        decrypted_data = Client.decrypt_hex(encrypted_data, password)
        print('decrypted_data: ', decrypted_data)
        Client.hex_to_file(filename, decrypted_data)

    @staticmethod
    def file_to_hex(filename):
        decode_hex = codecs.getdecoder("hex_codec")
        encode_hex = codecs.getencoder("hex_codec")
        with open(filename, 'rb') as file:
            data = file.read()
        print('file data: ', data)
        hex_data = encode_hex(data)[0].decode()
        return hex_data


    @staticmethod
    def hex_to_file(filename, hex_data):
        decode_hex = codecs.getdecoder("hex_codec")
        encode_hex = codecs.getencoder("hex_codec")
        raw_data = decode_hex(hex_data)[0]
        print('raw_data: ', raw_data)
        with open(filename, 'wb') as file:
            data = file.write(raw_data)


    @staticmethod
    def encrypt_hex(hex_data, password):
        cipher = AESCipher(key=password)
        encrypted_data = cipher.encrypt(hex_data)

        return encrypted_data.decode()

    @staticmethod
    def decrypt_hex(encrypted_data, password):
        cipher = AESCipher(key=password)
        decrypted_data = cipher.decrypt(encrypted_data)

        return decrypted_data


    def set_descr(self, cid, descr):
        message = "setDescr"+descr+self.get_time_stapm()
        url = self.domen + self.uri['account'] + '/descr'
        print(url)
        print('post request: ', self.domen + url)
        print('public key: ', self.public_key)
        print('cid: ', cid)
        print('descr: ', descr)
        print('message: ', message)
        print('signature: ', Qtum.sign_message(message, self.private_key))
        print('url: ', url)
        r = requests.post(url,
                          data={'public_key': self.public_key,
                                'message': message,
                                'signature': Qtum.sign_message(message, self.private_key),
                                'cid': cid,
                                'descr': descr
                                })
        response = r.json()
        #print(response)
        return response

    def get_descr(self, cid):
        cid = int(cid)
        message = 'getDescr' + self.get_time_stapm()
        params = '/?message=%s&signature=%s&cid=%d' % (message, Qtum.sign_message(message, self.private_key), cid)
        url = self.domen + self.uri['account'] + '/descr' + params
        print(url)
        r = requests.get(url)
        response = r.json()
        #print(response)
        return response

    def get_cid(self, ipfs_hash):
        return int(self.get_data_by_hash(ipfs_hash)['cid'])


    @staticmethod
    def lastblockid():
        url = Client.domen + Client.api_root + '/lastblockid'
        r = requests.get(url)
        print(url)
        response = r.json()
        #print(response)
        return response

    @staticmethod
    def ownerbycid(cid):
        cid = int(cid)
        params = '/?cid=%d' % cid
        url = Client.domen + Client.api_root + '/owner' + params
        print(url)
        r = requests.get(url)
        response = r.json()
        #print(response)
        return response






