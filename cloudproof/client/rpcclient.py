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
def readKey():
    f=open('key.pem','r')
    key=RSA.importKey(f.read())
    f.close()
    return key
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
    key=RSA.importKey(key)
    concat=str(block_Id)+str(key_block_Version_No)+str(new_Version_No)+new_Hash+encryptedEncodedContent
    h = SHA256.new(concat).hexdigest()
    sign=key.sign(h,'')
    return [picklethis(sign),h]
def decodeAndDecrypt(base64cipher,key,key_block_Version_No):
     base64decoded=base64.b64decode(base64cipher)
     key=AES.new(key, AES.MODE_CTR, counter=lambda: key_block_Version_No)
     decrypted=key.decrypt(base64decoded)
     print ("Decrypted:%s" %decrypted)
     return decrypted
def put(client_Put_Attest,block_Id,key_block_Version_No,new_Version_No,New_Hash,content,hashedSignedAttestation,hashSign):
    global cloudStorage
#    hash_object = hashlib.md5(content)
#    New_Hash=hash_object.hexdigest()
    key_block_Version_No=picklethis(key_block_Version_No)
    cloudReply=cloudStorage.put(client_Put_Attest,block_Id,key_block_Version_No,new_Version_No,New_Hash,content,hashedSignedAttestation,hashSign)
    return cloudReply
def get(block_Id):
    global cloudStorage
    [block_Version_No,content,hashSign,key_block_Version_No,cloud_Get_Attest]=cloudStorage.get(block_Id)
    key_block_Version_No=unpicklethis(key_block_Version_No)
    return [block_Version_No,content,hashSign,key_block_Version_No]
#Verify integiry of the block while reading a block.
def verifyIntegrity(block_Id,encryptedEncodedContent,hashSign):
    global keyDistributor
    key=keyDistributor.getPublicKey(block_Id,'u1')
    key=RSA.importKey(key)
    hashSign=unpicklethis(hashSign)
    h = SHA256.new(encryptedEncodedContent).hexdigest()
    return verifySignature(key,hashSign,h)
#    if (key.verify(h,hashSign)):
#        return 1
#    else:
#        return 0
def verifySignature(key,signedHash,hash):
    return key.verify(hash,signedHash)
pub_key=()
pri_key=()
#user='u1'
block_Id=1
rw='r'
key_block1_ver_no_init=os.urandom(16)
key_block2_ver_no_init=os.urandom(16)
key_block3_ver_no_init=os.urandom(16)
secretKey=cPickle.loads(keyDistributor.getSecretKey(1,'u1'))
content1=encryptAndEncode("Game of Thrones",unpicklethis(keyDistributor.getSecretKey(1,'u1')),key_block1_ver_no_init)
content2=encryptAndEncode("Narcos",unpicklethis(keyDistributor.getSecretKey(2,'u2')),key_block2_ver_no_init)
content3=encryptAndEncode("Breaking Bad",unpicklethis(keyDistributor.getSecretKey(3,'u3')),key_block3_ver_no_init)
while True:
    rw=raw_input("Read or Write?:")
    if rw == 'q':
        break

    if rw == 'w':
        [block_version_no,cipherContent,hashSign,key_block_Version_No]=get(block_Id)
        print ("Current Version:%s" %block_version_no)
        print ("Current Content:%s" %decodeAndDecrypt(cipherContent,secretKey,key_block_Version_No))
        if (verifyIntegrity(block_Id,cipherContent,hashSign)):
            print ("received integrity passed")
            newContent=raw_input("Lets Modify content to?:")
            content1=encryptAndEncode(newContent,secretKey,key_block_Version_No)
            print ("Encoded content1%s" %content1)
            put('client_put_attestation',block_Id,key_block_Version_No,block_version_no+1,'new Hash',content1,'Hashed_signed_attestation',hashAndSign(1,content1,'u1'))
            [block_version_no,cipherContent,hashSign,key_block_Version_No]=get(block_Id)
            print ("Updated Version:%s" %block_version_no)
            print ("Updated Content:%s" %decodeAndDecrypt(cipherContent,secretKey,key_block_Version_No))
            print ()
        else:
            print ("Received integrity failed: I hate Cloud.")
    elif rw == 'r':
        [clientputattestation1,hashOfElements]=createClientPutAttestation(1,picklethis(key_block1_ver_no_init),100,hash(content1),content1,'u1')
        new_Hash1=hash(content1)
#        print ("New Hash:%s" %new_Hash1)
#        clientputattestation2=createClientPutAttestation(2,key_block2_ver_no_init,100,hash(content2),content2,'u2')
#        new_Hash2=hash(content2)
#        clientputattestation3=createClientPutAttestation(3,key_block3_ver_no_init,100,hash(content3),content3,'u3')
#        new_Hash3=hash(content3)
        returnValue=put(clientputattestation1,1,key_block1_ver_no_init,100,new_Hash1,content1,clientputattestation1,hashAndSign(1,content1,'u1'))
        cloudPublicKey=unpicklethis(cloudStorage.getPublicKey())
        if verifySignature(cloudPublicKey,unpicklethis(returnValue),hashOfElements):
            print ("Cloud Put attestation looks good. I'll store it for later use")
#        put(clientputattestation2,2,key_block2_ver_no_init,100,hash(content2),content2,clientputattestation2,hashAndSign(2,content2,'u2'))
#        put(clientputattestation2,3,key_block3_ver_no_init,100,hash(content3),content3,clientputattestation3,hashAndSign(3,content3,'u3'))

