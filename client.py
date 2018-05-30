import json
import random
import time
import datetime
import requests
import pprint

from bip32keys import Bip32Keys

# TODO: import bip32keys from pip
# from bip32keys.bip32keys import Bip32Keys

pp = pprint.PrettyPrinter(indent=4)


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


class RequestType:
    get = 0
    post = 1
    put = 2


class PMESClientBackend(object):
    def __init__(self, host):
        self.host = host

        # Cookies.clear_all()

    @classmethod
    def _get_time_stamp(cls):
        ts = time.time()
        return datetime.datetime.fromtimestamp(ts).strftime('%Y%m%d%H%M')

    def _is_response_json(self, request):
        try:
            return request.json()
        except:
            return {"error": request.text}

    def _sign_message(self, message):
        message = json.dumps(message)
        keys = Cookies.get(Cookies.Type.keys)
        data = {
            "public_key": keys["public_key"],
            "message": message,
            "signature": Bip32Keys.sign_message(message, 
                            keys["private_key"])
        }

        return data

    def _send_request(self, request_type, endpoint, message=None):
        url = "%s%s" % (self.host, endpoint)

        time.sleep(2)
        if request_type == RequestType.get:
            request = requests.get(url, params=message)
        elif request_type == RequestType.post:
            request = requests.post(url, data=self._sign_message(message))
        elif request_type == RequestType.put:
            request = requests.put(url, data=self._sign_message(message))
        return self._is_response_json(request)

    def gen_keys(self):
        with open("cookies/generated.json") as generated:
            keys = random.choice(json.load(generated))
        Cookies.set(Cookies.Type.keys, keys)

    def fill_form(self, email, device_id, phone):
        data = {"email":email, "device_id":device_id}
        if phone:
            data.update({"phone":phone})

        Cookies.set(Cookies.Type.account, data)

    def create_account(self):
        Cookies.clear(Cookies.Type.cookies)

        endpoint = "/api/accounts"
        account = Cookies.get(Cookies.Type.account)
        message = {
                "timestamp":PMESClientBackend._get_time_stamp(),
                "email":account["email"],
                "device_id":account["device_id"]
            }
        if account["phone"]:
            message["phone"] = account["phone"]
        return self._send_request(RequestType.post, endpoint, message)

    def get_account_data(self):
        keys = Cookies.get(Cookies.Type.keys)
        endpoint = "/api/accounts/%s" % keys["public_key"]

        message = {"timestamp": PMESClientBackend._get_time_stamp(), "public_key": keys["public_key"]}
        return self._send_request(RequestType.get, endpoint, self._sign_message(message))

    def get_data_from_blockchain(self, _hash):
        if not _hash:
            return

        keys = Cookies.get(Cookies.Type.keys)
        endpoint = "/api/blockchain/%s/content" % keys["public_key"]

        message = {"hash": _hash}
        res = self._send_request(RequestType.get, endpoint, message)

        if res:
            if "error" in res.keys():
                return res

            cookies = Cookies.get(Cookies.Type.cookies)
            if _hash:
                cookies["hash"] = _hash

                if res["cid"] and isinstance(res["cid"], str) or isinstance(res["cid"], int):
                    cookies["cid"] = res["cid"]
                else:
                    cookies["cid"] = None

            Cookies.set(Cookies.Type.cookies, cookies)

        return res

    def post_data_to_blockchain(self, cus, price, description):
        keys = Cookies.get(Cookies.Type.keys)
        endpoint = "/api/blockchain/%s/content" % keys["public_key"]

        message = {
                "timestamp": PMESClientBackend._get_time_stamp(),
                "cus":cus,
                "price": price,
                "description": description
            }

        res = self._send_request(RequestType.post, endpoint, message)
        if res:
            if "error" in res.keys():
                return res

            _hash = None
            if "hash" in res.keys():
                _hash = res["hash"]

            cookies = Cookies.get(Cookies.Type.cookies)
            cookies["hash"] = _hash
            cookies["cid"] = None
            Cookies.set(Cookies.Type.cookies, cookies)

        return res

    def get_content_description(self, cid):
        endpoint = "/api/blockchain/%s/description" % cid
        return self._send_request(RequestType.get, endpoint)

    def set_content_description(self, cid, description):
        endpoint = "/api/blockchain/%s/description" % cid  
        message = {
                "timestamp":PMESClientBackend._get_time_stamp(),
                "cid":cid,
                "description": description,
            }
        return self._send_request(RequestType.post, endpoint, message)

    def get_content_price(self, cid):
        endpoint = "/api/blockchain/%s/price" % cid
        return self._send_request(RequestType.get, endpoint)

    def set_content_price(self, cid, price):
        endpoint = "/api/blockchain/%s/price" % cid  
        message = {
                "timestamp":PMESClientBackend._get_time_stamp(),
                "cid":cid,
                "price": price,
            }
        return self._send_request(RequestType.post, endpoint, message)

    def make_offer_from_buyer_to_seller(self, cid):
        keys = Cookies.get(Cookies.Type.keys)
        endpoint = "/api/blockchain/%s/offer" % keys["public_key"]
        message = {
                "timestamp":PMESClientBackend._get_time_stamp(),
                "cid":cid,
                "buyer_access_string": keys["public_key"],
            }
        return self._send_request(RequestType.post, endpoint, message)

    def make_offer_from_buyer_to_seller_with_price(self, cid, price):
        keys = Cookies.get(Cookies.Type.keys)
        endpoint = "/api/blockchain/%s/offer" % keys["public_key"] 
        message = {
                "timestamp":PMESClientBackend._get_time_stamp(),
                "cid":cid,
                "buyer_access_string": keys["public_key"],
                "offer_price":price
            }
        return self._send_request(RequestType.post, endpoint, message)

    def accept_offer_from_buyer(self, cid, buyer_pubkey):
        keys = Cookies.get(Cookies.Type.keys)
        endpoint = "/api/blockchain/%s/deal" % keys["public_key"]
        message = {
                "timestamp":PMESClientBackend._get_time_stamp(),
                "cid":cid,
                "buyer_access_string": keys["public_key"],
                "buyer_pubkey": buyer_pubkey
            }
        return self._send_request(RequestType.post, endpoint, message)

    def reject_offer_from_buyer(self, cid, buyer_addr):
        keys = Cookies.get(Cookies.Type.keys)
        endpoint = "/api/blockchain/%s/offer" % keys["public_key"]
        message = {
                "timestamp":PMESClientBackend._get_time_stamp(),
                "offer_id":{
                    "cid":cid,
                    "buyer_addr": buyer_addr
                }
            }
        return self._send_request(RequestType.put, endpoint, message)

    def reject_offer_from_owner(self, cid, buyer_addr):
        keys = Cookies.get(Cookies.Type.keys)
        endpoint = "/api/blockchain/%s/offer" % keys["public_key"]
        message = {
                "timestamp":PMESClientBackend._get_time_stamp(),
                "offer_id":{
                    "cid":cid,
                    "buyer_addr": buyer_addr
                }
            }
        return self._send_request(RequestType.put, endpoint, message)

    # Delete function when it becomes unnecessary
    def increment_balance(self, amount):
        res = self.get_account_data()
        if "error" in res.keys():
            return res
        uid = res["id"]
        endpoint = "/api/accounts/%s/balance" % uid
        url = "%s%s" % (self.host, endpoint)
        request = requests.post(url, data={"amount": amount})
        return self._is_response_json(request)

    def news(self):
        keys = Cookies.get(Cookies.Type.keys)
        endpoint = "/api/accounts/%s/news" % keys["public_key"]
        message = {
                "timestamp":PMESClientBackend._get_time_stamp()
            }
        return self._send_request(RequestType.get, endpoint, self._sign_message(message))

    def get_all_content(self):
        endpoint = "/api/blockchain/content"
        return self._send_request(RequestType.get, endpoint)


class PMESClient(object):
    def __init__(self, host="http://127.0.0.1:8000"):
        self.host = host
        self.client = PMESClientBackend(self.host)

    def gen_keys(self):
        self.client.gen_keys()

        print("Generating keys...")
        time.sleep(2)
        print("Public and private keys saved at 'cookies/keys.json' file.")

    def _input_variable(self, message, default=None):
        if default:
            if isinstance(default, str):
                message += " (default \"{}\"): ".format(default)
            else:
                message += " (default {}): ".format(default)
        else:
            message += ": "

        while True:
            var = input(message) or default
            if var:
                break
        return var

    def fill_form(self):
        email = self._input_variable("* Insert your e-mail: ")
        device_id = self._input_variable("* Insert your device id: ")
        phone = input("Insert your phone (optional): ")

        self.client.fill_form(email, device_id, phone)

        print("Account data submited.")

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
        print(" - make_offer_from_buyer_to_seller_with_price")
        print(" - accept_offer_from_buyer")
        print(" - reject_offer_from_buyer")
        print(" - reject_offer_from_owner")
        print(" - news")
        print(" - get_all_content")

    def create_account(self):
        res = self.client.create_account()
        pp.pprint(res)

    def get_account_data(self):
        res = self.client.get_account_data()
        pp.pprint(res)

    def get_data_from_blockchain(self):
        cookies = Cookies.get(Cookies.Type.cookies)
        _hash = self._input_variable("Hash", cookies.get("hash", None))

        if not _hash:
            print("Hash is empty")
            return

        res = self.client.get_data_from_blockchain(_hash)

        if not res:
            return

        if "error" in res.keys():
            if res["error"] == "Hash not found":
                print("Content is writing to the blockchain. Try to repeat request latter, please")
            else:
                print(res)
            return

        pp.pprint(res)
            
    def post_data_to_blockchain(self):
        cus = self._input_variable("* Content", "My favorite data")
        price = self._input_variable("* Price", 10)
        description = self._input_variable("* Description", "description")

        res = self.client.post_data_to_blockchain(cus, price, description)

        if not res:
            return

        if "error" in res.keys():
            print(res)
            return

        print("Hash = %s" % res["hash"])

    def get_content_description(self):
        cookies = Cookies.get(Cookies.Type.cookies)
        cid = self._input_variable("* CID", cookies.get("cid", None))
        res = self.client.get_content_description(cid)
        pp.pprint(res)

    def set_content_description(self):
        cookies = Cookies.get(Cookies.Type.cookies)
        description = self._input_variable("Description", "my description")
        cid = self._input_variable("* CID", cookies.get("cid", None))

        res = self.client.set_content_description(cid, description)
        pp.pprint(res)

    def get_content_price(self):
        cookies = Cookies.get(Cookies.Type.cookies)
        cid = self._input_variable("* CID", cookies.get("cid", None))
        res = self.client.get_content_price(cid)
        pp.pprint(res)

    def set_content_price(self):
        cookies = Cookies.get(Cookies.Type.cookies)
        price = self._input_variable("* Price", 100)
        cid = self._input_variable("* CID", cookies.get("cid", None))
        res = self.client.set_content_price(cid, price)
        print("\nYour price is: " + str(res["price"]))

    def make_offer_from_buyer_to_seller(self):
        cookies = Cookies.get(Cookies.Type.cookies)
        cid = self._input_variable("* CID")
        res = self.client.make_offer_from_buyer_to_seller(cid)
        pp.pprint(res)

    def make_offer_from_buyer_to_seller_with_price(self):
        cookies = Cookies.get(Cookies.Type.cookies)
        cid = self._input_variable("* CID")
        price = self._input_variable("* New price")
        res = self.client.make_offer_from_buyer_to_seller_with_price(cid, price)
        pp.pprint(res)

    def accept_offer_from_buyer(self):
        cookies = Cookies.get(Cookies.Type.cookies)
        cid = self._input_variable("* CID")
        buyer_pubkey = self._input_variable("* Buyer public key")
        res = self.client.accept_offer_from_buyer(cid, buyer_pubkey)
        pp.pprint(res)

    def reject_offer_from_buyer(self):
        cookies = Cookies.get(Cookies.Type.cookies)
        cid = self._input_variable("* CID")
        buyer_addr = self._input_variable("* Your address")
        res = self.client.reject_offer_from_buyer(cid, buyer_addr)
        pp.pprint(res)

    def reject_offer_from_owner(self):
        cookies = Cookies.get(Cookies.Type.cookies)
        cid = self._input_variable("* CID")
        buyer_addr = self._input_variable("* Buyer address")
        res = self.client.reject_offer_from_owner(cid, buyer_addr)
        pp.pprint(res)

    # Delete function when it becomes unnecessary
    def increment_balance(self):
        amount = self._input_variable("* Amount", 100)

        res = self.client.increment_balance(amount)

        if not res:
            return

        if "error" in res.keys():
            print(res)
            return

        print("\nBuyers balance is: " + str(res["amount"]))

    def news(self):
        res = self.client.news()
        pp.pprint(res)

    # TODO: Add Description when Artem fix it
    def get_all_content(self):
        res = self.client.get_all_content()
        if not res:
            return

        print("=======================   Content   =======================")
        print("Found {} items\n".format(len(res)))
        for content in res:
            # print("Description: {}".format(content["description"]))
            print("Owner: {}".format(content["owneraddr"]))
            print("Price: {}".format(content["price"]))
            print("cid: {}".format(content["cid"]))
            print()
