import requests, os, random, json, time, threading
from base64 import b64encode, b64decode
from nacl.public import SealedBox
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization
from nacl.encoding import RawEncoder
from nacl.signing  import VerifyKey

serverHost = 'http://localhost:5000'

threads_list = []
num_of_clients = 10

c_private_key_file_path = os.getcwd() + "/keys/client-{}_private_key.txt"
c_public_key_file_path = os.getcwd() + "/keys/client-{}_public_key.txt"


def newkeys():
    private = ed25519.Ed25519PrivateKey.generate()
    public = private.public_key()
    return public, private

def sign( message, priv_key ):
    return priv_key.sign(message)

def encrypt_and_sign_message( client_id, privateKey, serverPublicKey):
    # generate json message
    message = {}
    message['from'] = client_id
    message['amount'] = random.randint(1, 10000000)
    message['time'] = time.time()

    # sign message using client private key and using SHA-512
    signature = sign(json.dumps(message).encode('utf-8'), privateKey)

    # encrypt message using node public key
    nacl_pub = VerifyKey(key=serverPublicKey, encoder=RawEncoder)
    sealed_box = SealedBox(nacl_pub.to_curve25519_public_key())
    encrypt_message = sealed_box.encrypt(json.dumps(message).encode('utf-8'))
    return signature, encrypt_message, message

def generate_and_save_keys( c_id, c_priv_path=None, c_pub_path=None ):
    c_priv_path = c_priv_path.format(c_id) if c_priv_path else c_private_key_file_path.format(c_id)
    c_pub_path = c_pub_path.format(c_id) if c_pub_path else c_public_key_file_path.format(c_id)
    # Generate keys for client
    (publicKey, privateKey) = newkeys()
    private_bytes = privateKey.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption()
    )
    public_bytes = publicKey.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )
    open( c_priv_path,"wb" ).write(private_bytes)
    open( c_pub_path,"wb" ).write(public_bytes)
    return publicKey, privateKey

def worker( client_id, serverPublickKey ):
    # TODO: Need to send message every second for 1 minute
    (publicKey, privateKey) = generate_and_save_keys(client_id)
    for i in range(60):
        (signature, encrypt_message, message) = encrypt_and_sign_message( client_id, privateKey, serverPublickKey )
        # Sign the message using private Key
        transaction_message = {'client_id':client_id,'message':b64encode(encrypt_message).decode(),'signature':b64encode(signature).decode()}
        global serverHost
        res = requests.request(
                "POST",
                url= serverHost + '/add_transaction',
                json=transaction_message,
                headers = { 'Accept': 'text/plain'} )
        time.sleep(1)
        print(f"time: {time.time()}, client-id: {client_id}")



if __name__ == '__main__':
    server_public_key = open( os.getcwd() + "/keys/server_public_key.txt","rb").read()
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
