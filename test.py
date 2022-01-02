import unittest
from server import app, create_identity_and_blockchain, create_block, storeTransactionMessages, collection
from client import generate_and_save_keys, encrypt_and_sign_message, c_private_key_file_path, c_public_key_file_path
import os, random, time, string, json
from base64 import b64encode, b64decode
from unittest import mock
from nacl.public import SealedBox
from cryptography.hazmat.primitives import serialization
from nacl.encoding import RawEncoder
from nacl.signing  import VerifyKey

class BlockChainServerTests(unittest.TestCase):
    @classmethod
    def setUpClass(self):
        self.key_paths = []
        self.created_blocks = []
        
        # create client and server identities
        private_key_file_path = os.getcwd() + "/keys/testing_server_private_key.txt" 
        public_key_file_path = os.getcwd() + "/keys/testing_server_public_key.txt"
        (self.server_priv, self.server_pub) = create_identity_and_blockchain(private_key_file_path, public_key_file_path)
        self.key_paths.append( private_key_file_path )
        self.key_paths.append( public_key_file_path )
        self.server_public_bytes = self.server_pub.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        # for now taking only one clinet
        self.client_id = ''.join(random.choices(string.ascii_uppercase + string.digits, k=10))
        self.key_paths.append( c_private_key_file_path.format( self.client_id ) )
        self.key_paths.append( c_public_key_file_path.format( self.client_id ) )
        (self.client_pub, self.client_priv) = generate_and_save_keys( self.client_id )

        # Add Transactions and mine block for each 100 messages
        block_messages = []
        for i in range(800):
            message = {}
            message['from'] = ''.join(random.choices(string.ascii_uppercase + string.digits, k=10)) #Generating Random from
            message['amount'] = random.randint(1, 10000000)
            message['time'] = time.time()
            block_messages.append(json.dumps(message))
            if len(block_messages) == 100:
                block = create_block(block_messages)
                d_block = block.__dict__.copy()
                d_block['hash'] = b64encode(d_block['hash']).decode()
                d_block['previous_hash'] = b64encode(d_block['previous_hash']).decode() if isinstance(d_block['previous_hash'], bytes) else d_block['previous_hash']
                self.created_blocks.append(d_block)
                block_messages = []

        self.client = app.test_client(self)
    
    def test_blocks_count(self):
        response = self.client.get("/get_blocks_count")
        expected = dict(count=len(self.created_blocks) + 1,status=200)
        assert json.loads(response.data) == expected
    
    def test_get_block(self):
        response = self.client.get("/get_block?index=12")
        expected = dict(error="index should be less than blocks count", status=500)
        assert json.loads(response.data) == expected

    def test_get_block_chain(self):
        response = self.client.get("/get_chain")
        # Removing genesis block for assertion
        response_data = json.loads(response.data)
        response_data.pop(0)
        assert  response_data == self.created_blocks

    def test_get_previous_block(self):
        response = self.client.post("/get_previous_block", 
                        data=json.dumps({'hash':self.created_blocks[3]['hash']}), 
                        content_type='application/json')

        assert json.loads(response.data)  == self.created_blocks[2]
    
    def test_get_latest_block(self):
        response = self.client.get("/get_latest_block")
        assert json.loads(response.data)  == self.created_blocks[-1]
    
    # mocking mongo collection
    @mock.patch("server.collection")
    def test_add_transactions(self, mocked_collection):
        (signature, encrypt_message, message) = encrypt_and_sign_message(self.client_id, self.client_priv, self.server_public_bytes)
        response = self.client.post("/add_transaction", 
                        json={'client_id':self.client_id,'message':b64encode(encrypt_message).decode(),'signature':b64encode(signature).decode()}, 
                        content_type='application/json')
        expected = dict(message="Added transaction successfully", status=200)
        assert json.loads(response.data) == expected

    @mock.patch("server.collection")
    def test_add_transactions_wrong_message(self, mocked_collection):
        (signature, encrypt_message, message) = encrypt_and_sign_message(self.client_id, self.client_priv, self.server_public_bytes)
        nacl_pub = VerifyKey(key=self.server_public_bytes, encoder=RawEncoder)
        sealed_box = SealedBox(nacl_pub.to_curve25519_public_key())
        wrong_encrypt_message = sealed_box.encrypt(json.dumps({'from':'wrong client'}).encode('utf-8'))
        response = self.client.post("/add_transaction", 
                        json={'client_id':self.client_id,'message':b64encode(wrong_encrypt_message).decode(),'signature':b64encode(signature).decode()}, 
                        content_type='application/json')
        expected = dict(error="UnAuthorized", status=401)
        assert json.loads(response.data) == expected
    
    # mocking mongo collection
    @mock.patch("server.collection")
    def test_store_transaction_block(self, mocked_collection):
        mocked_collection.count_documents.return_value = 100
        mocked_messages = []
        for i in range(100):
            mocked_messages.append({'_id': ''.join(random.choices(string.ascii_lowercase + string.digits, k=10)), 
                'message': { 'from': ''.join(random.choices(string.ascii_uppercase + string.digits, k=10)), 
                            'amount': random.randint(1, 10000000), 'time': time.time()
                    }
            })
        mocked_collection.aggregate.return_value = mocked_messages
        block = storeTransactionMessages()
        assert block is not None

    @classmethod
    def tearDownClass(self):
        print("tearDownClass")
        for i in self.key_paths:
            if os.path.exists(i):
                os.remove(i)
        self.created_blocks = []
    
if __name__ == '__main__':
    unittest.main()
