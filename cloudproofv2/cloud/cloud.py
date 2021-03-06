import copy
import os
from Crypto.Hash import SHA256
from Crypto.Hash import SHA
from Crypto.PublicKey import RSA
import base64
import pickle as p
import hashlib
import xmlrpclib
from SimpleXMLRPCServer import SimpleXMLRPCServer
#set to 1 and cloud will send back wrong hash. actually will send back hash of next block
returnWrongHash=0
#Flag to change behavior of cloud for write serializibility. if 0 cloud will allow write on old versions.
simulateForkAttackFlag=int(0)
#initializing 5 blocks with initial values as null
#storage={1:[],2:[],3:[],4:[],5:[]}
keyDistributor = xmlrpclib.ServerProxy("http://localhost:8001/", allow_none=True)
storage={}
staleStorage={}
cloud_get_attestation='This is cloud put attestation'
#backupStorage will make copy of current contents at time x. so that when fork attack is simulated at time y we just return this copy (which is x). 
def backupStorage():
    global staleStorage
    staleStorage=copy.deepcopy(storage)
def simulateForkAttack(value):
    global simulateForkAttackFlag
    global storage
    storage={}
    storage=copy.deepcopy(staleStorage)
#    simulateForkAttackFlag=int(value)
#    print simulateForkAttackFlag
def getPublicKey():
     f=open('cloud.pub_key','r').read()
     key=RSA.importKey(f)
     return p.pickle(key)
def loadSigningKey():
    f=open('cloud.pri_key','r')
    key=RSA.importKey(f.read())
    f.close()
    return key
#Calculate hash of provided content
def hash(content):
    h = SHA256.new(content).hexdigest()
    return h
def blockExists(block_Id):
    if not storage.has_key(block_Id):
        return 0
    else:
        return 1
def put(client_Put_Attest,block_Id,key_block_Version_No,new_Version_No,New_Hash,content,hashSign,old_Hash):
    global staleStorage
    global storage
#verifySignature is used for integrity check of message. to make sure that privileged user sent this data update
    if verifySignature(block_Id,content,hashSign)==1:
        print ("Content Integrity Verified")
         #TODO Check write serializability. match hash(stored content) with new hash. 
        if storage.has_key(block_Id):
            [currBlock_Version_No,currContent,currHash,currHashSign,currKey_block_Version_No,currClient_Put_Attest,chain_Hash]=storage[block_Id]
#Cloud ensures write-serializibility  by checking if block_version number is +1
            if not (new_Version_No == currBlock_Version_No+1 and  old_Hash==currHash):
                return [0,"Cloud:Content already modified by other user. Try again",'no chain hash']
        else: #If this is new item. we assume first item from client will come with version number 1
                currBlock_Version_No=0
                currHash=''
                currHashSign=''
                chain_Hash=''
#write serializibility assurance. checking if old_hash given by client is same as currHash stored in storage
#        if not old_Hash==currHash:
#            return [0,"Cloud:Data has been updated, plz read again!",'no chain hash']
        [verifySuccessfullflag,cloudPutAttestation]=verifyClientPutAttestation(block_Id,key_block_Version_No,new_Version_No,New_Hash,content,client_Put_Attest,currHash,currHashSign)
        new_chain_Hash=hash(str(cloudPutAttestation)+str(chain_Hash))
        if verifySuccessfullflag==1:
            print ("Attestation Verified!")
#stale storage will be used to simulate fork attack. giving back stale data to reader. 
#            if storage.has_key(block_Id):
#                staleStorage[block_Id]=storage[block_Id]
            storage[block_Id]=[new_Version_No,content,New_Hash,hashSign,key_block_Version_No,client_Put_Attest,new_chain_Hash]
            #TODO store client put attestation somwhere.
            cloudPutAttestation=p.pickle(cloudPutAttestation)
            return [1,cloudPutAttestation,new_chain_Hash]
        else:
            print ("Attestation Failed! put operation denied")
            return [0,"Cloud:Attestation Failed! put operation denied",'no chain hash']
    else:
        print "Content Integrity check failed!"
        return [0,"Cloud:Content Integrity check failed!",'no chain hash']
def verifyClientPutAttestation(block_Id,key_block_Version_No,new_Version_No,New_Hash,encryptedEncodedContent,client_Put_Attest,currHash,currHashSign):
    global keyDistributor
    key=keyDistributor.getPublicKey(block_Id,'cloud')
    key=RSA.importKey(key)
    h=hash(encryptedEncodedContent)
    concat=str(block_Id)+str(key_block_Version_No)+str(new_Version_No)
#   sign=key.sign(h,'')
    hashOfElements=hash(concat)
#    new_chain_Hash=hash(client_Put_Attest+chain_Hash)
    hashOfCloudPutAttest=hash(concat)
#    hashOfElements=hash(concat+chain_Hash)
#Verifying if new hash is hash of block content
    if h == p.unpickle(New_Hash):
#Verifying verification of attestation signature
        if (key.verify(hashOfElements,p.unpickle(client_Put_Attest))):
            cloudSignKey=loadSigningKey()
            sign=cloudSignKey.sign(hashOfCloudPutAttest,'')
            return [1,sign]
        else:
            return [0,'nothing']
    else:
        print "New hash is not hash of block content"
        return [0,'nothing']
def get(block_Id,user,nonce):
    global staleStorage
    global storage
#This is to make sure that wrong hash is sent back so that client cries about integrity
    if (keyDistributor.hasAccess(block_Id,user,'r'))!=0:
        if returnWrongHash == 1:
            [block_Version_No,content,new_Hash,hashSign,key_block_Version_No,client_Put_Attest,chain_Hash]=storage[block_Id+1]
        else:
#            if simulateForkAttackFlag == 1:
#                print "hahaha given back stale data"
#                [block_Version_No,content,new_Hash,hashSign,key_block_Version_No,client_Put_Attest,chain_Hash]=staleStorage[block_Id]
#            else:
            [block_Version_No,content,new_Hash,hashSign,key_block_Version_No,client_Put_Attest,chain_Hash]=storage[block_Id]
    else:
        return [0,0,0,0,0,0,0]
#Get pickled form of cloud_get_attestation
    cloud_Get_Attest=createCloudGetAttestation(block_Id,key_block_Version_No,block_Version_No,content,chain_Hash,nonce)
    chain_Hash=hash(str(p.unpickle(cloud_Get_Attest))+chain_Hash)
#Need to update chain hash in stored value
    storage[block_Id]=[block_Version_No,content,new_Hash,hashSign,key_block_Version_No,client_Put_Attest,chain_Hash]
    return [block_Version_No,content,hashSign,key_block_Version_No,cloud_Get_Attest,chain_Hash,new_Hash]
#This is just integrity check
def createCloudGetAttestation(block_Id,key_block_Version_No,block_Version_No,content,chain_Hash,nonce):
    key=loadSigningKey()
    block_hash=p.pickle(hash(content))
    concat=str(block_Id)+str(key_block_Version_No)+str(block_Version_No)+nonce
    h = hash(concat)
    sign=key.sign(h,'')
    return p.pickle(sign)
def verifySignature(block_Id,encryptedEncodedContent,hashSign):
    global keyDistributor
    key=keyDistributor.getPublicKey(block_Id,'cloud')
    key=RSA.importKey(key)
    hashSign=p.unpickle(hashSign)
    h = SHA256.new(encryptedEncodedContent).hexdigest()
    if (key.verify(h,hashSign)):
        return 1
    else:
        return 0
server = SimpleXMLRPCServer(("localhost", 8000), allow_none=True,logRequests=False)
print ("Listening on port 8000...")
server.register_function(put, "put")
server.register_function(get, "get")
server.register_function(getPublicKey, "getPublicKey")
server.register_function(blockExists,"blockExists")
server.register_function(simulateForkAttack,"simulateForkAttack")
server.register_function(backupStorage,"backupStorage")
server.serve_forever()
