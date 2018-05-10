from AESCipher import AESCipher
import codecs
import time
import datetime
from qtum_utils.qtum import Qtum
from client import Client
from time import sleep
from jsonrpcclient.http_client import HTTPClient
password = 'my secret password'


def main():

    q = Qtum({'wif': 'cVqhhLYPNb48nXZH1KQffoN6riquKCpn6TDGdYj1F52SBP4hVUJB'}, mainnet=False)
    print(q.get_uncompressed_public_key())

    # c = Client(Qtum('hfjkdsfjadsfjdsaofellohellohjfskljdsfcds'))
    # c.create('my_dev', 'emaildsf')
    # print(c.get_account())
    #
    # ipfs_hash =  c.upload_file('user1', password)['hash']
    # print('hash: ', ipfs_hash)
    # sleep(300)
    # cid = int(c.get_cid(ipfs_hash))
    # print(cid)
    #
    # c.download_file('testfile_downloaded', password, cid)
    # c.set_descr(cid, 'Descrioption sample')
    # sleep(300)
    # response = c.get_descr(cid)
    # print('get_descr: ', response)
    #
    # Client.ownerbycid(cid)



if __name__=='__main__':
    main()