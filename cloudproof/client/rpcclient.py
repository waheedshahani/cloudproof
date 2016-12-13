import random 
from Crypto.Hash import SHA256
from Crypto.Signature import PKCS1_PSS
from Crypto.Hash import SHA
import cPickle
import hashlib
import xmlrpclib
import base64
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto.Util import Counter
import os
cloudStorage = xmlrpclib.ServerProxy("http://localhost:8000/", allow_none=True)
keyDistributor = xmlrpclib.ServerProxy("http://localhost:8001/", allow_none=True)
key_block_Version_No_inti=[os.urandom(16),os.urandom(16),os.urandom(16),os.urandom(16)]

def picklethis(object):
    with open('temp','w') as temp:
        cPickle.dump(object,temp)
    f=open('temp','r').read()
    return f
def unpicklethis(object):
    return cPickle.loads(object)
#def readKey():
#    f=open('key.pem','r')
#    key=RSA.importKey(f.read())
#    f.close()
#    return key
def encryptAndEncode(plainText,key,key_block_Version_No):
    key=AES.new(key, AES.MODE_CTR, counter=lambda: key_block_Version_No)
    encrypted=key.encrypt(plainText)
    b64=base64.b64encode(encrypted)
    return b64
#This will return hash of content. passed as New_Hash to cloud. 
def hash(encryptedEncodedContent):
    h = SHA256.new(encryptedEncodedContent).hexdigest()
    return picklethis(h)
def hashAndSign(blockId,encryptedEncodedContent,user):
    global keyDistributor
    key=keyDistributor.getSigningKey(blockId,user)
    key=RSA.importKey(key)
    h = SHA256.new(encryptedEncodedContent).hexdigest()
    sig = key.sign(h,'')
    return picklethis(sig)
def createClientPutAttestation(block_Id,key_block_Version_No,new_Version_No,new_Hash,encryptedEncodedContent,user):
    global keyDistributor
    key=keyDistributor.getSigningKey(block_Id,user)
    if key ==0:
        return [0,0]
    key=RSA.importKey(key)
    concat=str(block_Id)+str(key_block_Version_No)+str(new_Version_No)+new_Hash+encryptedEncodedContent
    h = SHA256.new(concat).hexdigest()
    sign=key.sign(h,'')
    return [picklethis(sign),h]
def genNonce(length=8):
    """Generate pseudo-random number."""
    return ''.join([str(random.randint(0, 9)) for i in range(length)])
def decodeAndDecrypt(base64cipher,key,key_block_Version_No):
     base64decoded=base64.b64decode(base64cipher)
     key=AES.new(key, AES.MODE_CTR, counter=lambda: key_block_Version_No)
     decrypted=key.decrypt(base64decoded)
     print ("Decrypted:%s" %decrypted)
     return decrypted
def put(client_Put_Attest,block_Id,key_block_Version_No,new_Version_No,New_Hash,content,hashedSignedAttestation,hashSign):
    global cloudStorage
    key_block_Version_No=picklethis(key_block_Version_No)
    [returnCode,cloudReply,chain_Hash]=cloudStorage.put(client_Put_Attest,block_Id,key_block_Version_No,new_Version_No,New_Hash,content,hashedSignedAttestation,hashSign)
    return [returnCode,cloudReply,chain_Hash]
def get(block_Id):
    global cloudStorage
    nonce=genNonce()
    [block_Version_No,content,hashSign,key_block_Version_No,cloud_Get_Attest]=cloudStorage.get(block_Id,nonce)
    return [block_Version_No,content,hashSign,key_block_Version_No,cloud_Get_Attest,nonce]
#Verify integiry of the block while reading a block.
def verifyIntegrity(block_Id,encryptedEncodedContent,hashSign):
    global keyDistributor
    key=keyDistributor.getPublicKey(block_Id,'u1')
    key=RSA.importKey(key)
    hashSign=unpicklethis(hashSign)
    h = SHA256.new(encryptedEncodedContent).hexdigest()
    return verifySignature(key,hashSign,h)
def verifySignature(key,signedHash,hash):
    return key.verify(hash,signedHash)
def verifyCloudGetAttestation(block_Id,block_Version_No,cipherContent,key_block_Version_No,cloud_Get_Attest,nonce):
    global cloudStorage
    key=unpicklethis(cloudStorage.getPublicKey())
    block_hash=hash(cipherContent)
    concat=str(block_Id)+str(key_block_Version_No)+str(block_Version_No)+block_hash+nonce
    hashOfElements=unpicklethis(hash(concat))
#Verifying verification of attestation signature
    if (key.verify(hashOfElements,unpicklethis(cloud_Get_Attest))):
        return 1
    else:
        return 0
block_Id=1
user='u1'
print ("Enter p to populate cloud with dummy data. w for write, r for read, q to quit")
while True:
    rw=raw_input("p|r|w|q?:")
    if rw == 'q':
        break
    if rw == 'w':
        block_Id=0
        secretKey=unpicklethis(keyDistributor.getSecretKey(block_Id,user))
        [block_Version_No,cipherContent,hashSign,key_block_Version_No,cloud_Get_Attest,nonce]=get(block_Id)
        print ("Current Block Version:%s" %block_Version_No)
        print ("Current Content:%s" %decodeAndDecrypt(cipherContent,secretKey,unpicklethis(key_block_Version_No)))
        if (verifyIntegrity(block_Id,cipherContent,hashSign)):
            print ("received content integrity check passed")
            #Now we need to verify integrity of client_get_attestation
            if verifyCloudGetAttestation(block_Id,block_Version_No,cipherContent,key_block_Version_No,cloud_Get_Attest,nonce):
                print ("cloud Get attestation verified! will store attestation")
                newContent=raw_input("Lets Modify content to?:")
                key_block_ver_no=str(os.urandom(16))
                block_Version_No=block_Version_No+1
                content=encryptAndEncode(newContent,secretKey,key_block_ver_no)
                new_Hash=hash(content)
                [clientputattestation,hashOfElements]=createClientPutAttestation(block_Id,picklethis(key_block_ver_no),block_Version_No,new_Hash,content,user)
                if clientputattestation==0:
                    print ("User %s has no write privileges for Block:%d" %(user,block_Id))
                else:
                    [returnCode,cloudReply,chain_Hash]=put(clientputattestation,block_Id,key_block_ver_no,block_Version_No,new_Hash,content,clientputattestation,hashAndSign(block_Id,content,user))
                    if returnCode == 1:
                        cloudPublicKey=unpicklethis(cloudStorage.getPublicKey())
                        if verifySignature(cloudPublicKey,unpicklethis(cloudReply),hashOfElements):
                            print ("Cloud Put attestation looks good. I'll store it for later use")
                    else:
                        print cloudReply
            else:
                print ("Cloud Get attestation failed for Block:%s" %block_Id)

        else:
            print ("Received integrity failed: I hate Cloud.")
    elif rw == 'r':
        block_Id=0
        secretKey=unpicklethis(keyDistributor.getSecretKey(block_Id,user))
        [block_Version_No,cipherContent,hashSign,key_block_Version_No,cloud_Get_Attest,nonce]=get(block_Id)
        print ("Current Block Version:%s" %block_Version_No)
        print ("Current Content:%s" %decodeAndDecrypt(cipherContent,secretKey,unpicklethis(key_block_Version_No)))
        if (verifyIntegrity(block_Id,cipherContent,hashSign)):
            print ("received content integrity check passed")
            #Now we need to verify integrity of client_get_attestation
            if verifyCloudGetAttestation(block_Id,block_Version_No,cipherContent,key_block_Version_No,cloud_Get_Attest,nonce):
                print ("cloud Get attestation verified! will store attestation")
            else:
                print ("Cloud Get attestation failed for Block:%s" %block_Id)
    elif rw=='p':
        putcontents=['Game of Thrones','Narcos','Breaking Bad','The Walking Dead','Stranger things']
        block_Version_No=1 # Initial version number.
        for block_Id in range(0, 1):
            secretKey=cPickle.loads(keyDistributor.getSecretKey(block_Id,user))
            key_block_ver_no=str(os.urandom(16))
            content=encryptAndEncode(putcontents[block_Id],unpicklethis(keyDistributor.getSecretKey(block_Id,user)),key_block_ver_no)
            new_Hash=hash(content)
            [clientputattestation,hashOfElements]=createClientPutAttestation(block_Id,picklethis(key_block_ver_no),block_Version_No,new_Hash,content,user)
            if clientputattestation==0:
                print ("User %s has no write privileges for Block:%d" %(user,block_Id))
            else:
                [returnCode,cloudReply,chain_Hash]=put(clientputattestation,block_Id,key_block_ver_no,block_Version_No,new_Hash,content,clientputattestation,hashAndSign(block_Id,content,user))
                cloudPublicKey=unpicklethis(cloudStorage.getPublicKey())
#                print chain_Hash
                if verifySignature(cloudPublicKey,unpicklethis(cloudReply),hashOfElements):
                    print ("Cloud Put attestation looks good. I'll store it for later use")
                else:
                    print ("Cloud Put attestation verification error")
#        exit()
#        key_block1_ver_no_init=os.urandom(16)
#        key_block2_ver_no_init=os.urandom(16)
#        key_block3_ver_no_init=os.urandom(16)
#        secretKey=cPickle.loads(keyDistributor.getSecretKey(1,'u1'))
#        content1=encryptAndEncode("Game of Thrones",unpicklethis(keyDistributor.getSecretKey(1,'u1')),key_block1_ver_no_init)
#        content2=encryptAndEncode("Narcos",unpicklethis(keyDistributor.getSecretKey(2,'u2')),key_block2_ver_no_init)
#        content3=encryptAndEncode("Breaking Bad",unpicklethis(keyDistributor.getSecretKey(3,'u3')),key_block3_ver_no_init)
#        [clientputattestation1,hashOfElements]=createClientPutAttestation(1,picklethis(key_block1_ver_no_init),100,hash(content1),content1,'u1')
#        new_Hash1=hash(content1)
#        cloudReply=put(clientputattestation1,1,key_block1_ver_no_init,100,new_Hash1,content1,clientputattestation1,hashAndSign(1,content1,'u1'))
#        cloudPublicKey=unpicklethis(cloudStorage.getPublicKey())
#        if verifySignature(cloudPublicKey,unpicklethis(cloudReply),hashOfElements):
#            print ("Cloud Put attestation looks good. I'll store it for later use")
