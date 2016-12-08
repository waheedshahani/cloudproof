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
#key=cPickle.loads(keyDistributor.getKey(1,'r','u1'))
ctr=os.urandom(16)
#cipher = AES.new(key, AES.MODE_CTR, counter=lambda: ctr)
#ct = cipher.encrypt("asdk")
#print (str(ct))
#print ("decrypted")

#dcipher = AES.new(key, AES.MODE_CTR, counter=lambda: ctr)
#print (dcipher.decrypt(ct))
#exit()

def readKey():
    f=open('key.pem','r')
    key=RSA.importKey(f.read())
    f.close()
    return key

def encryptAndEncode(plainText,key):
    key=AES.new(key, AES.MODE_CTR, counter=lambda: ctr)
    encrypted=key.encrypt(plainText)
    b64=base64.b64encode(encrypted)
    return b64
def hashAndSign(blockId,encryptedEncodedContent):
    global keyDistributor
    signingKey=cPickle.loads(keyDistributor.getSigningKey(1,user))
    print signingKey
    hashOfContent= hashlib.md5(encryptedEncodedContent)
    HexHash=hashOfContent.hexdigest()
    print HexHash
    HexHash="SHAHANI WAHEED ALI"
    #hexstr=str.encode(HexHash)
    #b64Hash=base64.b64encode(hexstr)
    type(HexHash)    
    signed=signingKey.encrypt(HexHash,32)[0]
    b64=base64.b64encode(signed)
    print "Base 64%s" %b64
    return "test"
    return b64
def decodeAndDecrypt(base64cipher,key):
     base64decoded=base64.b64decode(base64cipher)
     key=AES.new(key, AES.MODE_CTR, counter=lambda: ctr)
     decrypted=key.decrypt(base64decoded)
     print ctr
     print ("Decrypted:%s" %decrypted)
     return decrypted
def put(client_Put_Attest,block_Id,key_block_Version_No,new_Version_No,New_Hash,content,hashedSignedAttestation,hashSign):
    global cloudStorage
    hash_object = hashlib.md5(content)
    New_Hash=hash_object.hexdigest()
    cloudStorage.put(client_Put_Attest,block_Id,key_block_Version_No,new_Version_No,New_Hash,content,hashedSignedAttestation,hashSign)
def get(block_Id):
    global cloudStorage
    [block_Version,content,cloud_get_attestation]=cloudStorage.get(block_Id)
    return [block_Version,content,cloud_get_attestation]
   
pub_key=()
pri_key=()
user='u1'
block_id=1
#rw='w'
#user=raw_input("Enter user name u1,u2,u3?:")
#block_id=raw_input("Enter block ID:")
rw=raw_input("Read or Write?:")
secretKey=cPickle.loads(keyDistributor.getSecretKey(1,'u1'))
#secretKey=AES.new(key, AES.MODE_CTR, counter=lambda: ctr)

#pub_key=cPickle.loads(keyDistributor.getKey(1,'r',user))
#encryptedContent=encryptAndEncode("WAHEED ENCRYPTED",pub_key)
#put(block_id,block_version,encryptedContent)
content1=encryptAndEncode("Game of Thrones",secretKey)
content2=encryptAndEncode("Narcos",secretKey)
content3=encryptAndEncode("Breaking Bad",secretKey)
if rw == 'w':
    #pri_key=cPickle.loads(keyDistributor.getKey(1,'w',user))
    [block_version_no,cipherContent,cloud_get_attestation]=get(block_id)
    print ("Current Version:%s" %block_version_no)
    print ("Current Content:%s" %decodeAndDecrypt(cipherContent,secretKey))
    print ("Cloud Get Attestation:%s" %cloud_get_attestation)
    newContent=raw_input("Lets Modify content to?:")
    encryptedContent=encryptAndEncode(newContent,secretKey)
    put('client_put_attestation',block_id,' ',block_version_no+1,'new Hash',encryptedContent,'Hashed_signed_attestation')
    [block_version_no,cipherContent,cloud_get_attestation]=get(block_id)
    print ("Current Version:%s" %block_version_no)
    print ("Current Content:%s" %decodeAndDecrypt(cipherContent,secretKey))
    print ("Cloud Get Attestation:%s" %cloud_get_attestation)
else:
    hashAndSign(1,content1)
    put('client_put_attestation',1,' ',100,'new Hash',content1,'Hashed_signed_attestation',hashAndSign(1,content1))
#    put('client_put_attestation',2,' ',100,'new Hash',content2,'Hashed_signed_attestation',hashAndSign(2,content2))
#    put('client_put_attestation',3,' ',100,'new Hash',content3,'Hashed_signed_attestation',hashAndSign(3,content3))

    #put(1,100,encryptAndEncode("Game of Thrones",pub_key),"CPA")
    #put(2,100,encryptAndEncode("Narcos",pub_key),"CPA")
    #put(3,100,encryptAndEncode("Breaking Bad",pub_key),"CPA")
    #put(1,101,encryptAndEncode("Game of Thrones",pub_key),"CPA")

#print ("Decrypting data")
#for i in range(1,4):
#   print (get(i))
