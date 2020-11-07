import socket
import os
from Crypto.Cipher import AES
prim_key=b'1234567890123456'



def keyGenerator():
    key = os.urandom(16)
    return key

def encrypt_key(key):
    cyph=AES.new(prim_key,AES.MODE_ECB)
    return cyph.encrypt(key)
    
#connecting to A, generating an encrypting a key, and sending it
def connecting():
    host = socket.gethostname()  
    port = 5006
    csocket = socket.socket()  
    csocket.connect((host, port))  
    asked_for_key = csocket.recv(1024).decode()  
    if asked_for_key == "ECB" or asked_for_key == "CFB":
        K=keyGenerator()
        print("k: ")
        print (K)
        K=encrypt_key(K)
        print ("Encrypted key: \n")
        print(K)
        csocket.send(K)

if __name__ == '__main__':
    connecting()
