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
import pickle as p
cloudStorage = xmlrpclib.ServerProxy("http://localhost:8000/", allow_none=True)
keyDistributor = xmlrpclib.ServerProxy("http://localhost:8001/", allow_none=True)
promptUsername=1
class cloudUser():
#Variables so far username,block_Id,secretKey
    def __init__(self,username):
        self.username=username
    def setBlockID(self,block_Id):
        self.block_Id=block_Id
    def setSecretKey(self):
        self.secretKey=p.unpickle(keyDistributor.getSecretKey(self.block_Id,self.username))
    def setNonce(self,length=8):
        """Generate pseudo-random number."""
        self.nonce=''.join([str(random.randint(0, 9)) for i in range(length)])
        return self.nonce
    def get(self):
        if cloudStorage.blockExists(self.block_Id):
            self.nonce=self.setNonce()
            [self.block_Version_No,self.b64,self.hashSign,self.key_block_Version_No,self.cloud_Get_Attest,self.chain_Hash]=cloudStorage.get(self.block_Id,self.username,self.nonce)
            self.setSecretKey()
            self.decodeAndDecrypt()
            self.hashSign=p.unpickle(self.hashSign)
        else:
            print "I need to put dummy record first"
    
    def verifyIntegrity(self):
        self.blockPublicKey=keyDistributor.getPublicKey(self.block_Id,self.username)
        self.blockPublicKey=RSA.importKey(self.blockPublicKey)
        self.block_hash = SHA256.new(self.b64).hexdigest()
        return self.blockPublicKey.verify(self.block_hash,self.hashSign)
#        return verifySignature(key,hashSign,h)
    def verifyCloudGetAttestation(self):
        self.cloudPublicKey=p.unpickle(cloudStorage.getPublicKey())
        block_hashPickled=p.pickle(self.block_hash)
        self.key_block_Version_NoPickled=p.pickle(self.key_block_Version_No)
        self.concat=str(self.block_Id)+str(self.key_block_Version_NoPickled)+str(self.block_Version_No)+block_hashPickled+self.nonce+self.chain_Hash
        self.hashOfElements=SHA256.new(self.concat).hexdigest()
#Verifying verification of attestation signature
        if (self.cloudPublicKey.verify(self.hashOfElements,p.unpickle(self.cloud_Get_Attest))):
            return 1
        else:
            return 0
    def setNewkey_block_Version_No(self):
        self.key_block_Version_No=str(os.urandom(16))

    def createClientPutAttestation(self):
        self.setSecretKey()
        self.setNewkey_block_Version_No()
        self.encryptAndEncode()
        self.blockSigningKey=keyDistributor.getSigningKey(self.block_Id,self.username)
        if self.blockSigningKey == 0:
            return 0
        self.blockSigningKey=RSA.importKey(self.blockSigningKey)
        self.block_hash=SHA256.new(self.b64).hexdigest()
        self.block_hashPickled=p.pickle(self.block_hash)
        self.concat=str(self.block_Id)+str(p.pickle(self.key_block_Version_No))+str(self.block_Version_No)+self.block_hashPickled
        self.hashOfElements=SHA256.new(self.concat).hexdigest()
        self.clientPutAttestation=self.blockSigningKey.sign(self.hashOfElements,'')
        return 1
#    concat=str(block_Id)+str(key_block_Version_No)+str(new_Version_No)+new_Hash+encryptedEncodedContent
    def put(self,client_Put_Attest,block_Id,key_block_Version_No,new_Version_No,New_Hash,content,hashSign):
        [returnCode,cloudReply,chain_Hash]=cloudStorage.put(client_Put_Attest,block_Id,p.pickle(self.key_block_Version_No),new_Version_No,New_Hash,self.b64,hashSign)
        if returnCode==1:
            keyDistributor.putAttestations(self.username,"cloudputattestation",self.block_Id,self.block_Version_No,cloudReply)
#            keyDistributor.putAttestations(self.username,"clientputattestation",self.block_Id,self.block_Version_No,client_Put_Attest)
        return [returnCode,cloudReply,chain_Hash]

    def encryptAndEncode(self):
        self.secretKey=AES.new(self.secretKey, AES.MODE_CTR, counter=lambda: self.key_block_Version_No)
        self.encryptedContent=self.secretKey.encrypt(self.content)
        self.b64=base64.b64encode(self.encryptedContent)
#        return b64
    def decodeAndDecrypt(self):
        self.encryptedContent=base64.b64decode(self.b64)
        self.key_block_Version_No=p.unpickle(self.key_block_Version_No)
        self.secretKey=AES.new(self.secretKey, AES.MODE_CTR, counter=lambda: self.key_block_Version_No)
        self.content=self.secretKey.decrypt(self.encryptedContent)

obj=cloudUser('u1')
#user=user1.user
def encryptAndEncode(plainText,key,key_block_Version_No):
    key=AES.new(key, AES.MODE_CTR, counter=lambda: key_block_Version_No)
    encrypted=key.encrypt(plainText)
    b64=base64.b64encode(encrypted)
    return b64
def decodeAndDecrypt(base64cipher,key,key_block_Version_No):
     base64decoded=base64.b64decode(base64cipher)
     key=AES.new(key, AES.MODE_CTR, counter=lambda: key_block_Version_No)
     decrypted=key.decrypt(base64decoded)
     return decrypted
#This will return hash of content. passed as New_Hash to cloud. 
def hash(input):
    h = SHA256.new(input).hexdigest()
    return h
def hashAndSign(blockId,encryptedEncodedContent,user):
    global keyDistributor
    key=keyDistributor.getSigningKey(blockId,user)
    key=RSA.importKey(key)
    h = hash(encryptedEncodedContent)
    sig = key.sign(h,'')
    return sig
def createClientPutAttestation(block_Id,concatenatedItems,user):
    key=keyDistributor.getSigningKey(block_Id,user)
    if key ==0:
        return [0,0]
    key=RSA.importKey(key)
#    concat=str(block_Id)+str(key_block_Version_No)+str(new_Version_No)+new_Hash+encryptedEncodedContent
    h = hash(concatenatedItems)
    sign=key.sign(h,'')
    return [sign,h]
def genNonce(length=8):
    """Generate pseudo-random number."""
    return ''.join([str(random.randint(0, 9)) for i in range(length)])

#Verify integiry of the block while reading a block.
def verifyIntegrity(block_Id,encryptedEncodedContent,hashSign,user):
    global keyDistributor
    key=keyDistributor.getPublicKey(block_Id,user)
    key=RSA.importKey(key)
    hashSign=p.unpickle(hashSign)
    h = SHA256.new(encryptedEncodedContent).hexdigest()
    return verifySignature(key,hashSign,h)
def verifySignature(key,signedHash,hash):
    return key.verify(hash,signedHash)
def verifyCloudGetAttestation(block_Id,block_Version_No,cipherContent,key_block_Version_No,cloud_Get_Attest,nonce,chain_Hash):
    global cloudStorage
    key=p.unpickle(cloudStorage.getPublicKey())
    block_hash=p.pickle(hash(cipherContent))
    concat=str(block_Id)+str(key_block_Version_No)+str(block_Version_No)+block_hash+nonce+chain_Hash
    hashOfElements=hash(concat)
#Verifying verification of attestation signature
    if (key.verify(hashOfElements,p.unpickle(cloud_Get_Attest))):
        return 1
    else:
        return 0
def put(client_Put_Attest,block_Id,key_block_Version_No,new_Version_No,New_Hash,content,hashSign,user):
#    self.setSecretKey()
#    self.setNewkey_block_Version_No()
    key_block_Version_No=p.pickle(key_block_Version_No)
    [returnCode,cloudReply,chain_Hash]=cloudStorage.put(client_Put_Attest,block_Id,key_block_Version_No,new_Version_No,New_Hash,content,hashSign)
    if returnCode==1:
        keyDistributor.putAttestations(user,"cloudputattestation",'dummy',cloudReply)
        keyDistributor.putAttestations(user,"clientputattestation",'dummy',client_Put_Attest)
    return [returnCode,cloudReply,chain_Hash]
def get(block_Id,user):
    global cloudStorage
    nonce=genNonce()
    [block_Version_No,content,hashSign,key_block_Version_No,cloud_Get_Attest,chain_Hash]=cloudStorage.get(block_Id,user,nonce)
    if content !=0:
        keyDistributor.putAttestations(user,"cloudgetattestation",'dummy',cloud_Get_Attest)
    return [block_Version_No,content,hashSign,key_block_Version_No,cloud_Get_Attest,nonce,chain_Hash]


print ("Enter p to populate cloud with dummy data. w for write, r for read,f to simulate Fork attack, q to quit")
while True:
    obj.username=raw_input("User [u1]?") or "u1"
    rw=raw_input("p|r|w|q?:")
    if rw == 'q':
        break
    if rw == 'w':
        obj.setBlockID(int(raw_input("Block ID(0|1|2...):?:")))
#        obj.setSecretKey()
        obj.get()
        if (obj.b64==0):
            print "User has no privileges"
            continue
        print ("Current Block Version:%s" %obj.block_Version_No)
        print ("Current Content:%s" %obj.content)
        if (obj.verifyIntegrity()):
            print ("received content integrity check passed")
            #Now we need to verify integrity of client_get_attestation
            if obj.verifyCloudGetAttestation():
                print ("cloud Get attestation verified! will store attestation")
                obj.content=raw_input("Lets Modify content to?:")
#                obj.setNewkey_block_Version_No()
                obj.block_Version_No=obj.block_Version_No+1
#                obj.block_Version_No=int(raw_input("current Block version: %s,Enter New:" %obj.block_Version_No))
                if obj.createClientPutAttestation()==0:
                    print ("User %s has no write privileges for Block:%d" %(obj.username,obj.block_Id))
                else:
                    [returnCode,cloudReply,chain_Hash]=obj.put(p.pickle(obj.clientPutAttestation),obj.block_Id,obj.key_block_Version_No,obj.block_Version_No,obj.block_hashPickled,obj.content,p.pickle(hashAndSign(obj.block_Id,obj.b64,obj.username)))

    #                [returnCode,cloudReply,chain_Hash]=put(p.pickle(obj.clientPutAttestation),obj.block_Id,obj.key_block_Version_No,obj.block_Version_No,obj.block_hashPickled,obj.content,p.pickle(hashAndSign(obj.block_Id,obj.content,obj.username)),obj.username)

                    if returnCode == 1:
                        cloudPublicKey=p.unpickle(cloudStorage.getPublicKey())
                        obj.hashOfElements=hash(obj.concat+chain_Hash)
                        if verifySignature(cloudPublicKey,p.unpickle(cloudReply),obj.hashOfElements):
                            print ("Cloud Put attestation for Block %s looks good. I'll store it for later use" %obj.block_Id)
                        else:
                            print ("Cloud Put attestation verification failed for Block %s however cloud has put the item" %obj.block_Id)
                    else:
                        print cloudReply
            else:
                print ("Cloud Get attestation failed for Block:%s" %obj.block_Id)

        else:
            print ("Received integrity failed for Block %s I hate Cloud." %obj.block_Id)
    elif rw == 'r':
        obj.setBlockID(int(raw_input("Block ID(0|1|2...):?:")))
#        obj.setSecretKey()
        obj.get()
        if (obj.b64==0):
            print "User has no privileges"
            continue
        print ("Current Block Version:%s" %obj.block_Version_No)
        print ("Current Content:%s" %obj.content)        
        if (obj.verifyIntegrity()):
            print ("received content integrity check passed")
            #Now we need to verify integrity of client_get_attestation
            if obj.verifyCloudGetAttestation():
                print ("cloud Get attestation verified! will store attestation")
            else:
                print ("Cloud Get attestation failed for Block:%s" %obj.block_Id)
        else:
            print ("Received integrity failed for Block %s I hate Cloud." %obj.block_Id)
    elif rw=='p':
        for block_Id in range(0, 5):
            obj.setBlockID(block_Id)
            obj.block_Version_No=0
            obj.content=''
            if obj.createClientPutAttestation()==0:
                print ("User %s has no write privileges for Block:%d" %(obj.username,obj.block_Id))
            else:
                [returnCode,cloudReply,chain_Hash]=obj.put(p.pickle(obj.clientPutAttestation),obj.block_Id,obj.key_block_Version_No,obj.block_Version_No,obj.block_hashPickled,obj.content,p.pickle(hashAndSign(obj.block_Id,obj.b64,obj.username)))

                if returnCode == 1:
                    cloudPublicKey=p.unpickle(cloudStorage.getPublicKey())
                    obj.hashOfElements=hash(obj.concat+chain_Hash)
                    if verifySignature(cloudPublicKey,p.unpickle(cloudReply),obj.hashOfElements):
                        print ("Cloud Put attestation for Block %s looks good. I'll store it for later use" %obj.block_Id)
                    else:
                        print ("Cloud Put attestation verification failed for Block %s however cloud has put the item" %obj.block_Id)
                else:
                    print cloudReply
    elif rw=='f':
        value=raw_input("Simulate Fork Attack y|n?:")
        if value=='y':
            cloudStorage.simulateForkAttack(1)
            print "Cloud will give you stale information for last modified block"
        elif value=='n':
            cloudStorage.simulateForkAttack(0)
            print "Cloud will not give you stale information"
    elif rw=='ws': #this will run method on auditor for write serializibility check
        keyDistributor.DoesWSViolate()
