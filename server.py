from flask import Flask, jsonify, request, Response
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA512, SHA384, SHA256, SHA, MD5
from Crypto import Random
from base64 import b64encode, b64decode
import json
from schema import Schema, And, Use, Optional, SchemaError
from blockchain import Blockchain
import os
from pymongo import MongoClient

blockchain = None

# default path
default_private_key_path = os.getcwd() + "/keys/server_private_key.pem" 
default_public_key_path = os.getcwd() + "/keys/server_public_key.pem"

keysize = 2048

# Expected Message Schema
conf_message_schema = Schema({
	'from': And(Use(str)),
	'amount': And(Use(int)),
	'time': And(Use(float))
})

server_private_path = None
server_public_path = None


def create_identity_and_blockchain( private_path=None, public_path=None ):
	
	# create and store keys in a local file storage
	global server_private_path
	server_private_path = private_path = private_path if private_path else default_private_key_path
	global server_public_path
	server_public_path = public_path = public_path if public_path else default_public_key_path
	random_generator = Random.new().read
	key = RSA.generate( keysize, random_generator )
	private, public = key, key.publickey()
	private_pem = private.export_key().decode()
	public_pem = public.export_key().decode()
	open( private_path, "w" ).write( private_pem )
	open( public_path, "w" ).write( public_pem )
	
	# Initialize block chain
	global blockchain
	blockchain = Blockchain( private ) #using the private key for signing the hash and persist signed hash in block
	return private, public;


app = Flask(__name__)

# Initialize Mongo
client = MongoClient('localhost', 27017)
collection = client.blockchaindb.transaction

# EndPoints
@app.route('/get_chain', methods=['GET'])
def get_chain():
	try:
		chain_snapshot = blockchain.chain
		dict_chain = [dict_block(block) for block in chain_snapshot]
		return jsonify(dict_chain)
	except Exception as e:
		return jsonify(status=500, error="Unknown Error" + str(e))

@app.route('/get_blocks_count', methods=['GET'])
def get_blocks_count():
	try:
		return jsonify( count = len(blockchain.chain), status=200)
	except Exception as e:
		return jsonify( status=500, error="Cannot get block chain count" + str(e))

@app.route('/get_latest_block', methods=['GET'])
def get_latest_block():
	try:
		latest_block = blockchain.get_last_blockchain_value()
		return dict_block(latest_block)
	except Exception as e:
		return jsonify( status=500, error="Cannot get latest block" + str(e))


@app.route('/get_block', methods=['GET'])
def get_block():
	# Index starts with 0
	try:
		index = request.args['index']
		if int(index) < len(blockchain.chain):
			block = blockchain.chain[int(index)]
			return dict_block(block)
		else:
			return jsonify(error="index should be less than blocks count", status=500)
	except Exception as e:
		return jsonify( status=500, error="Cannot get block by index" + str(e))

@app.route('/get_previous_block', methods=['POST'])
def get_previos_block():
	try:
		request_data = request.get_json()
		prev_block = None
		if request_data['hash']:
			for i in range(0, len(blockchain.chain) ):        
				block = blockchain.chain[i]
				if block.hash == b64decode(request_data['hash']):
					prev_block = blockchain.chain[i-1]
					return dict_block(prev_block)
			return jsonify( error="cannot find previous block for given hash", status=500 )
		else:
			return jsonify( error="please provide hash of block", status=500 )
	except Exception as e:
		return jsonify( status=500, error="Cannot get block by index" + str(e))

@app.route('/add_transaction', methods=['POST'])
def add_transaction():
	try:
		request_data = request.get_json()
		# Decrypt Message
		path = server_private_path if server_private_path else default_private_key_path
		server_private_key = RSA.import_key( open( path, "r" ).read() )
		cipher = PKCS1_OAEP.new( server_private_key )
		decrypted_message = cipher.decrypt( b64decode( request_data['message'] ) )
		validation = validate_request( decrypted_message, request_data )
		if validation:
			# add transaction to mongodb
			storeTransactionMessages( json.loads(decrypted_message) )
		else:
			return jsonify( error="UnAuthorized", status=401 )
					
		return jsonify( message="Added transaction successfully", status=200 )
	except Exception as e:
		return jsonify( status=500, error="Exception: Cannot add transaction, " + str(e))


# Methods
def dict_block(block):
	d_block = block.__dict__.copy()
	d_block['hash'] = b64encode(d_block['hash']).decode()
	d_block['previous_hash'] = b64encode(d_block['previous_hash']).decode() if isinstance(d_block['previous_hash'], bytes) else d_block['previous_hash']
	return d_block
	
def storeTransactionMessages( message=None ):
	
	# Storing messages in mongo and if messages > 100 then mining block
	client_rec = { "message": message }
	inserted = collection.insert_one(dict(client_rec))
	count = collection.count_documents({})
	if count == 100:
		remove_ids = []
		trans_messages = []
		records = collection.aggregate([
						{ "$limit" : 100 }
					]);
		for rec in records:
			# For now for hashing converting json message to string
			trans_messages.append(json.dumps(rec.get('message')))
			remove_ids.append(rec.get('_id'))
		block = create_block( trans_messages )
		if block != None:
			# delete already processed transaction
			collection.delete_many({'_id': {'$in': remove_ids}})
		else:
			print("Mining failes for transactions list",trans_messages)
		return block
	return None
		

def create_block( block_messages ):
	# mine block with transactions
	blockchain.add_open_transactions(block_messages)
	return blockchain.mine_block()

def verify( message, signature, pub_key ):
	signer = PKCS1_v1_5.new(pub_key)
	digest = SHA512.new() #By default considering 512 hash for now
	digest.update(message)
	return signer.verify(digest, signature)

def validate_request( decrypted_message, request_data ):
	# Validate message schema
	transaction_message = json.loads( decrypted_message )
	try:
		conf_message_schema.validate(transaction_message)
		# Validate amount shouldn't be negative
		if transaction_message['amount'] < 0:
			return False
	except SchemaError:
		return False
		
	# Validate signature and check came from correct client
	client_public_key = RSA.import_key( open( os.getcwd() + "/keys/client-" + request_data['client_id'] + "_public_key.pem","r" ).read() )
	verifySig = verify( decrypted_message, b64decode( request_data['signature'] ), client_public_key)
	if not verifySig:
		return False
	return True


# main driver function
if __name__ == '__main__':
	
	# generate keys and initialize block chain
	create_identity_and_blockchain()
	app.run()
