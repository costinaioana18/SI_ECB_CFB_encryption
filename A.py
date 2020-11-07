import os
import socket
import random
import string
from Crypto.Cipher import AES
prim_key=b'1234567890123456'


#the functions splits a message in blocks of 16 
def split_blocks(message):
    return [message[i:i+16] for i in range(0, len(message), 16)]

def XoR(t1,t2):
    return bytes([_a ^ _b for _a, _b in zip(t1, t2)])

def IVGenerator():
    iv = ''.join(random.SystemRandom().choice(string.ascii_letters + string.digits) for _ in range(16))
    #print(iv)
    iv=bytes(iv,'utf-8')
    return iv

#ECB encrypting algorithm
def ECBencode(plain_text,key):
    print("\n ...encrypting using ECB...\n")
    wholeCipherText=b''
    plain_blocks=split_blocks(plain_text)
    for plain_block in plain_blocks:
        plain_block=plain_block.encode()
        ciphertext=XoR(plain_block,key)
        wholeCipherText+=ciphertext[0:16]
        #print(ciphertext)
    #print(wholeCipherText)
    return wholeCipherText

#ECB decrypting algortihm
def ECBdecode(wholeCipherText,key):
    print("\n ...decrypting using ECB...\n")
    wholePlainText=''
    wholeCipherText=split_blocks(wholeCipherText)
    for cipher in wholeCipherText:
        plain=XoR(cipher,key)
        wholePlainText+=plain.decode()
    #print(wholePlainText)
    return wholePlainText


#CFB encrypting algorithm
def CFBencode(plain_text,key,initVector):
    print("\n ...encrypting using CFB...\n")
    wholeCipherText=b''
    plain_blocks=split_blocks(plain_text)
    for plain_block in plain_blocks:
        plain_block=plain_block.encode()
        #print(plain_block)
        ciphertext=XoR(initVector,key)
        ciphertext=XoR(plain_block,ciphertext)
        wholeCipherText+=ciphertext[0:16]
        #print(ciphertext)
        initVector=ciphertext
    #print(wholeCipherText)
    return wholeCipherText

#CFB decoding algorithm
def CFBdecode(wholeCipherText,key,initVector):
    print("\n ...decrypting using CFB...\n")
    wholePlainText=''
    wholeCipherText=split_blocks(wholeCipherText)
    for cipher in wholeCipherText:
        plain=XoR(initVector,key)
        plain=XoR(cipher,plain)
        initVector=cipher
        wholePlainText+=plain.decode()
    #print(wholePlainText)
    return wholePlainText

#returns true if B confirms receiving the encryption method
def confirm(conn):
    enc_meth = conn.recv(1024).decode()
    if enc_meth == 'ECB' or enc_meth == 'CFB':
        print("B confirmed recieving the encryption method.\n")
        return True
    print("Something is wrong!.\n")
    return False

#the function decrypts the key using the prim_key
def decrypt_key(key):
    cyph=AES.new(prim_key,AES.MODE_ECB)
    return cyph.decrypt(key)
    
#the server program, which communicates with KM in order to get a key he sends to be, among the encryption method
#after everyting is set up and the communication is initialised by B, they star communicating throught ecrypted messages 
def myEncryptor():
    #at first, we create the socket in order to connect with both B and KM
    host = socket.gethostname()
    port = 5006
    print("Waiting for the Key Manager and B to connect.\n")
    ssocket = socket.socket()
    ssocket.bind((host, port))
    ssocket.listen(2)
    conn_b, address_b = ssocket.accept()
    conn_km, address_km = ssocket.accept()
    print("Connected with the Key Manager and with B.\n")
    #We select our encryption method, we send it to B, and we ask for a key
    enc_method = input('Do you want to have you messages encrypted using ECB or CFB?\n')
    while(enc_method!='ECB' and enc_method!='CFB'):
        print(enc_method)
        enc_method = input('That was not a valid encryption method. Try ECB or CFB\n')
    conn_b.send(enc_method.encode()) 
    print("Waiting for B to confirm the encryption method.\n")
    if not confirm(conn_b):
        exit(0)

    print("Asking the Key Manager for a key\n")
    conn_km.send(enc_method.encode())  
    encrypted_key = conn_km.recv(1024) 
    print( "We recieved the key from the KM. ")
    #print(encrypted_key)
    if not encrypted_key :
        print("Something is wrong! We didn't recieve the key :( \n")
        exit(1)

    print("\nSending the encrypted key to B",end='')
    conn_b.send(encrypted_key)
    IV=IVGenerator()
    conn_b.send(IV)

    #conn_b.send(prim_key)

    decrypted_key=decrypt_key(encrypted_key)
    print("\nWe decrypted the key\n")
    #print(decrypted_key)

    #after everything it set up, we wait for B to initiate the communication
    print("\nWaiting for B to initiate the communication.",end='')
    if conn_b.recv(1024).decode() == "start":
        print("\n You can start communicating right now! Send your first message:")
        while True:
            #our messaje is encrypted using the chosen method
            message = input('Me: ')
            if(message=="quit"):
                conn_b.close()
                exit(2)

            if enc_method=="ECB":
                c=ECBencode(message,decrypted_key)
            else:
                initVector=IV
                c=CFBencode(message,decrypted_key,initVector)

                
            conn_b.send(c)  # send data to the client

            
            received_message = conn_b.recv(1024)
            if not received_message:
                # if data is not received or message to end comm was sent -> break
                break
            if enc_method=="ECB":
                received_message=ECBdecode(received_message,decrypted_key)
            else:
                initVector=IV
                #print(initVector)
                received_message=CFBdecode(received_message,decrypted_key,initVector)
            
            print("B: " + str(received_message))
    else:
        print("B is not ready to communicate. Terminating program")
        exit(2)

    conn_b.close()  # close the connection


if __name__ == '__main__':
    myEncryptor()
