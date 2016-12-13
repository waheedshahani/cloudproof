
from Crypto.Hash import SHA256
from Crypto.Hash import SHA
from Crypto.PublicKey import RSA
import base64
import cPickle
import hashlib
import xmlrpclib
from SimpleXMLRPCServer import SimpleXMLRPCServer
#set to 1 and cloud will send back wrong hash. actually will send back hash of next block
returnWrongHash=0
#initializing 5 blocks with initial values as null
#storage={1:[],2:[],3:[],4:[],5:[]}
keyDistributor = xmlrpclib.ServerProxy("http://localhost:8001/", allow_none=True)
storage={}
cloud_get_attestation='This is cloud put attestation'
def getPublicKey():
     f=open('cloud.pub_key','r').read()
     key=RSA.importKey(f)
     return picklethis(key)
def loadSigningKey():
    f=open('cloud.pri_key','r')
    key=RSA.importKey(f.read())
    f.close()
    return key
#Calculate hash of provided content
def hash(content):
    h = SHA256.new(content).hexdigest()
    return h
def picklethis(object):
    with open('temp','w') as temp:
        cPickle.dump(object,temp)
    f=open('temp','r').read()
    return f
def unpicklethis(object):
    return cPickle.loads(object)
def put(client_Put_Attest,block_Id,key_block_Version_No,new_Version_No,New_Hash,content,hashedSignedAttestation,hashSign):
#verifySignature is used for integrity check of message. to make sure that privileged user sent this data update
    if verifySignature(block_Id,content,hashSign)==1:
        print ("Content Integrity Verified")
         #TODO Check write serializability. match hash(stored content) with new hash. 
        if storage.has_key(block_Id):
            [currBlock_Version_No,currContent,currHash,currHashSign,currKey_block_Version_No,currClient_Put_Attest]=storage[block_Id]
            if new_Version_No != currBlock_Version_No+1:
                 return [0,"Content already modified by other user. Try again",'no chain hash']
        else: #If this is new item. we assume first item from client will come with version number 1
                currBlock_Version_No=0
                currHash=''
                currHashSign=''
        [verifySuccessfullflag,cloudPutAttestation,chain_Hash]=verifyClientPutAttestation(block_Id,key_block_Version_No,new_Version_No,New_Hash,content,client_Put_Attest,currHash,currHashSign)
        if verifySuccessfullflag==1:
            print ("Attestation Verified!")
            storage[block_Id]=[new_Version_No,content,New_Hash,hashSign,key_block_Version_No,client_Put_Attest]
            #TODO store client put attestation somwhere.
            cloudPutAttestation=picklethis(cloudPutAttestation)
            print ("Data updated to block %s . Will send back cloud put attestation" %block_Id)
            return [1,cloudPutAttestation,chain_Hash]
        else:
            print ("Attestation Failed! put operation denied")
            return [0,"Attestation Failed! put operation denied",'no chain hash']
    else:
        print "Content Integrity check failed!"
        return [0,"Content Integrity check failed!",'no chain hash']
def verifyClientPutAttestation(block_Id,key_block_Version_No,new_Version_No,New_Hash,encryptedEncodedContent,client_Put_Attest,currHash,currHashSign):
    global keyDistributor
    key=keyDistributor.getPublicKey(block_Id,'cloud')
    key=RSA.importKey(key)
    h=hash(encryptedEncodedContent)
    print currHashSign
    concat=str(block_Id)+str(key_block_Version_No)+str(new_Version_No)+New_Hash+encryptedEncodedContent
#   sign=key.sign(h,'')
    hashOfElements=hash(concat)
    chain_Hash=hash(encryptedEncodedContent+currHash)
#Verifying if new hash is hash of block content
    if h == unpicklethis(New_Hash):
#Verifying verification of attestation signature
        if (key.verify(hashOfElements,unpicklethis(client_Put_Attest))):
            cloudSignKey=loadSigningKey()
            sign=cloudSignKey.sign(hashOfElements,'')
            return [1,sign,chain_Hash]
        else:
            return [0,'nothing',chain_Hash]
def get(block_Id,nonce):
    [block_Version_No,content,new_Hash,hashSign,key_block_Version_No,client_Put_Attest]=storage[block_Id]
#This is to make sure that wrong hash is sent back so that client cries about integrity
    if returnWrongHash == 1:
        [block_Version_No,content,new_Hash,hashSign,key_block_Version_No,client_Put_Attest]=storage[block_Id+1]
#Get pickled form of cloud_get_attestation
    cloud_Get_Attest=createCloudGetAttestation(block_Id,key_block_Version_No,block_Version_No,content,nonce)
    return [block_Version_No,content,hashSign,key_block_Version_No,cloud_Get_Attest]
#This is just integrity check
def createCloudGetAttestation(block_Id,key_block_Version_No,block_Version_No,content,nonce):
    key=loadSigningKey()
    block_hash=picklethis(hash(content))
    concat=str(block_Id)+str(key_block_Version_No)+str(block_Version_No)+block_hash+nonce
    h = hash(concat)
    sign=key.sign(h,'')
    return picklethis(sign)
def verifySignature(block_Id,encryptedEncodedContent,hashSign):
    global keyDistributor
    key=keyDistributor.getPublicKey(block_Id,'cloud')
    key=RSA.importKey(key)
    hashSign=unpicklethis(hashSign)
    h = SHA256.new(encryptedEncodedContent).hexdigest()
    if (key.verify(h,hashSign)):
        return 1
    else:
        return 0
server = SimpleXMLRPCServer(("localhost", 8000), allow_none=True)
print ("Listening on port 8000...")
server.register_function(put, "put")
server.register_function(get, "get")
server.register_function(getPublicKey, "getPublicKey")
server.serve_forever()
