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

def picklethis(object):
    with open('temp','w') as temp:
        cPickle.dump(object,temp)
    f=open('temp','r').read()
    os.remove('temp')
    return f
def unpicklethis(object):
    return cPickle.loads(object)
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
def createClientPutAttestation(block_Id,concatenatedItems,user):
    global keyDistributor
    key=keyDistributor.getSigningKey(block_Id,user)
    if key ==0:
        return [0,0]
    key=RSA.importKey(key)
#    concat=str(block_Id)+str(key_block_Version_No)+str(new_Version_No)+new_Hash+encryptedEncodedContent
    h = SHA256.new(concatenatedItems).hexdigest()
    sign=key.sign(h,'')
    return [picklethis(sign),h]
def genNonce(length=8):
    """Generate pseudo-random number."""
    return ''.join([str(random.randint(0, 9)) for i in range(length)])
def decodeAndDecrypt(base64cipher,key,key_block_Version_No):
     base64decoded=base64.b64decode(base64cipher)
     key=AES.new(key, AES.MODE_CTR, counter=lambda: key_block_Version_No)
     decrypted=key.decrypt(base64decoded)
     return decrypted
def put(client_Put_Attest,block_Id,key_block_Version_No,new_Version_No,New_Hash,content,hashedSignedAttestation,hashSign):
    global cloudStorage
    key_block_Version_No=picklethis(key_block_Version_No)
    [returnCode,cloudReply,chain_Hash]=cloudStorage.put(client_Put_Attest,block_Id,key_block_Version_No,new_Version_No,New_Hash,content,hashedSignedAttestation,hashSign)
    return [returnCode,cloudReply,chain_Hash]
def get(block_Id):
    global cloudStorage
    nonce=genNonce()
    [block_Version_No,content,hashSign,key_block_Version_No,cloud_Get_Attest,chain_Hash]=cloudStorage.get(block_Id,nonce)
    return [block_Version_No,content,hashSign,key_block_Version_No,cloud_Get_Attest,nonce,chain_Hash]
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
def verifyCloudGetAttestation(block_Id,block_Version_No,cipherContent,key_block_Version_No,cloud_Get_Attest,nonce,chain_Hash):
    global cloudStorage
    key=unpicklethis(cloudStorage.getPublicKey())
    block_hash=hash(cipherContent)
    concat=str(block_Id)+str(key_block_Version_No)+str(block_Version_No)+block_hash+nonce+chain_Hash
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
        [block_Version_No,cipherContent,hashSign,key_block_Version_No,cloud_Get_Attest,nonce,chain_Hash]=get(block_Id)
        print ("Current Block Version:%s" %block_Version_No)
        print ("Current Content:%s" %decodeAndDecrypt(cipherContent,secretKey,unpicklethis(key_block_Version_No)))
        if (verifyIntegrity(block_Id,cipherContent,hashSign)):
            print ("received content integrity check passed")
            #Now we need to verify integrity of client_get_attestation
            if verifyCloudGetAttestation(block_Id,block_Version_No,cipherContent,key_block_Version_No,cloud_Get_Attest,nonce,chain_Hash):
                print ("cloud Get attestation verified! will store attestation")
                newContent=raw_input("Lets Modify content to?:")
                key_block_Version_No=str(os.urandom(16))
                block_Version_No=block_Version_No+1
                content=encryptAndEncode(newContent,secretKey,key_block_Version_No)
                new_Hash=hash(content)
                concatenatedItems=str(block_Id)+str(picklethis(key_block_Version_No))+str(block_Version_No)+new_Hash+content
                [clientputattestation,hashOfElements]=createClientPutAttestation(block_Id,concatenatedItems,user)
                if clientputattestation==0:
                    print ("User %s has no write privileges for Block:%d" %(user,block_Id))
                else:
                    [returnCode,cloudReply,chain_Hash]=put(clientputattestation,block_Id,key_block_Version_No,block_Version_No,new_Hash,content,clientputattestation,hashAndSign(block_Id,content,user))
                    if returnCode == 1:
                        cloudPublicKey=unpicklethis(cloudStorage.getPublicKey())
                        hashOfElements=unpicklethis(hash(concatenatedItems+chain_Hash))
                        if verifySignature(cloudPublicKey,unpicklethis(cloudReply),hashOfElements):
                            print ("Cloud Put attestation for Block %s looks good. I'll store it for later use" %block_Id)
                        else:
                            print ("Cloud Put attestation verification failed for Block %s however cloud has put the item" %block_Id)
                    else:
                        print cloudReply
            else:
                print ("Cloud Get attestation failed for Block:%s" %block_Id)

        else:
            print ("Received integrity failed for Block %s I hate Cloud." %block_Id)
    elif rw == 'r':
        block_Id=0
        secretKey=unpicklethis(keyDistributor.getSecretKey(block_Id,user))
        [block_Version_No,cipherContent,hashSign,key_block_Version_No,cloud_Get_Attest,nonce,chain_Hash]=get(block_Id)
        print ("Current Block Version:%s" %block_Version_No)
        print ("Current Content:%s" %decodeAndDecrypt(cipherContent,secretKey,unpicklethis(key_block_Version_No)))
        if (verifyIntegrity(block_Id,cipherContent,hashSign)):
            print ("received content integrity check passed for Block %s" %block_Id)
            #Now we need to verify integrity of client_get_attestation
            if verifyCloudGetAttestation(block_Id,block_Version_No,cipherContent,key_block_Version_No,cloud_Get_Attest,nonce,chain_Hash):
                print ("cloud Get attestation for Block %s verified! will store attestation" %block_Id)
            else:
                print ("Cloud Get attestation failed for Block %s" %block_Id)
        else:
            print ("received content integrity failed for Block %s" %block_Id)
    elif rw=='p':
        putcontents=['Game of Thrones','Narcos','Breaking Bad','The Walking Dead','Stranger things']
        new_Version_No=1 # Initial version number.
        for block_Id in range(0, 5):
            secretKey=cPickle.loads(keyDistributor.getSecretKey(block_Id,user))
            key_block_Version_No=str(os.urandom(16))
            content=encryptAndEncode(putcontents[block_Id],unpicklethis(keyDistributor.getSecretKey(block_Id,user)),key_block_Version_No)
            new_Hash=hash(content)
            concatenatedItems=str(block_Id)+str(picklethis(key_block_Version_No))+str(new_Version_No)+new_Hash+content
            [clientputattestation,hashOfElements]=createClientPutAttestation(block_Id,concatenatedItems,user)
            if clientputattestation==0:
                print ("User %s has no write privileges for Block:%d" %(user,block_Id))
            else:
                [returnCode,cloudReply,chain_Hash]=put(clientputattestation,block_Id,key_block_Version_No,new_Version_No,new_Hash,content,clientputattestation,hashAndSign(block_Id,content,user))
                cloudPublicKey=unpicklethis(cloudStorage.getPublicKey())
                hashOfElements=unpicklethis(hash(concatenatedItems+chain_Hash))
                if verifySignature(cloudPublicKey,unpicklethis(cloudReply),hashOfElements):
                    print ("Cloud Put attestation for Block %s looks good. I'll store it for later use" %block_Id)
                else:
                    print ("Cloud Put attestation verification error for Block %s" %block_Id)
