import requests, os, random, json, time, threading
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA512, SHA256
from Crypto import Random
from base64 import b64encode, b64decode

serverHost = 'http://localhost:5000'
keysize = 2048

threads_list = []
num_of_clients = 10

c_private_key_file_path = os.getcwd() + "/keys/client-{}_private_key.pem"
c_public_key_file_path = os.getcwd() + "/keys/client-{}_public_key.pem"


def newkeys():
    global keysize
    random_generator = Random.new().read
    key = RSA.generate(keysize, random_generator)
    private, public = key, key.publickey()
    return public, private

def sign( message, priv_key, hashAlg ):
    signer = PKCS1_v1_5.new(priv_key)
    if (hashAlg == "SHA-512"):
        digest = SHA512.new()
    else:
        digest = SHA256.new() #for now default will be sha256
    digest.update(message)
    return signer.sign(digest)

def encrypt_and_sign_message( client_id, privateKey, serverPublicKey):
    # generate json message
    message = {}
    message['from'] = client_id
    message['amount'] = random.randint(1, 10000000)
    message['time'] = time.time()

    # sign message using client private key and using SHA-512
    signature = sign(json.dumps(message).encode('utf-8'), privateKey, "SHA-512")

    # encrypt message using node public key
    cipher = PKCS1_OAEP.new(serverPublicKey)
    encrypt_message = cipher.encrypt(json.dumps(message).encode('utf-8'))
    return signature, encrypt_message, message

def generate_and_save_keys( c_id, c_priv_path=None, c_pub_path=None ):
    c_priv_path = c_priv_path.format(c_id) if c_priv_path else c_private_key_file_path.format(c_id)
    c_pub_path = c_pub_path.format(c_id) if c_pub_path else c_public_key_file_path.format(c_id)
    # Generate keys for client
    (publicKey, privateKey) = newkeys()
    private_pem = privateKey.export_key().decode()
    public_pem = publicKey.export_key().decode()
    open( c_priv_path,"w" ).write(private_pem)
    open( c_pub_path,"w" ).write(public_pem)
    return publicKey, privateKey

def worker( client_id, serverPublickKey ):
    # TODO: Need to send message every second for 1 minute
    (publicKey, privateKey) = generate_and_save_keys(client_id)
    for i in range(60):
        (signature, encrypt_message, message) = encrypt_and_sign_message( client_id, privateKey, serverPublickKey )
        # Sign the message using private Key
        transaction_message = {'client_id':client_id,'message':b64encode(encrypt_message),'signature':b64encode(signature)}
        global serverHost
        res = requests.request(
                "POST",
                url= serverHost + '/add_transaction',
                json=transaction_message,
                headers = { 'Accept': 'text/plain'} )
        time.sleep(1)
        print(f"time: {time.time()}, client-id: {client_id}")



if __name__ == '__main__':
    server_public_key = RSA.import_key(open( os.getcwd() + "/keys/server_public_key.pem","r").read())
    for num in range(num_of_clients):
        client_id = str(num+1)
        # Call worker
        thread = threading.Thread(target=worker, args=(client_id, server_public_key,))
        threads_list.append(thread)

    # Start the threads (i.e. calculate the random number lists)
    for thread in threads_list:
        thread.start()
        time.sleep(1)

    # Ensure all of the threads have finished
    for thread in threads_list:
        thread.join()
    
    print("all clients finished")