import socket
from Crypto.Cipher import AES

start_communicating = "start"
prim_key=b'1234567890123456'

#the functions splits a message in blocks of 16
def split_blocks(message):
    return [message[i:i+16] for i in range(0, len(message), 16)]


def XoR(t1,t2):
    return bytes([_a ^ _b for _a, _b in zip(t1, t2)])

#ECB encypting algorithm
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

def getInitVector():
    return b'a1s2d3d4f5f6g7h8'

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

def decrypt_key(key):
    cyph=AES.new(prim_key,AES.MODE_ECB)
    return cyph.decrypt(key)
    
#the client program, which connect to the server, in order to receive the encryption method, and to initiate the communication
def myEncryptor():
    #connecting to the server
    host = socket.gethostname() 
    port = 5006

    csocket = socket.socket()
    csocket.connect((host, port))
    #receiving and confirming the encryption method
    enc_method = csocket.recv(1024).decode()
    print('We recieved the encryption method: '+enc_method)
    csocket.send(enc_method.encode())

    #receiving and decrypting the key
    encrypted_key = csocket.recv(1024)
    
    print("\nWe recieved the key!")
    IV = csocket.recv(1024)
    decrypted_key=decrypt_key(encrypted_key)
    #print("decrypted key: ")
    #print(decrypted_key)

    #sending the starting signal
    ready=input("Are you ready to communicate? Yes/no!\n")
    while(ready!="yes"):
        ready=input("Are you ready to communicate? Yes/no!\n")
    csocket.send(start_communicating.encode())

    #comunibationg with A through encrypted messages
    while True:
        recv_message = csocket.recv(1024)  # receive response
        if not recv_message:
            print("A closed the communication.")
            break

        if enc_method=="ECB":
            recv_message=ECBdecode(recv_message,decrypted_key)
        else:
            
            initVector=IV
            #print(initVector)
            recv_message=CFBdecode(recv_message,decrypted_key,initVector)
        
        print('A: ' + recv_message)  # show in terminal
        my_message = input("Me: ")

        if enc_method=="ECB":
            c=ECBencode(my_message,decrypted_key)
        else:
            
            initVector=IV
            c=CFBencode(my_message,decrypted_key,initVector)
        
        csocket.send(c)  # send message

    csocket.close()  # close the connection


if __name__ == '__main__':
    myEncryptor()
