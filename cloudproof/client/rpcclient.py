import cPickle
import xmlrpclib
import base64
from Crypto.PublicKey import RSA
cloudStorage = xmlrpclib.ServerProxy("http://localhost:8000/", allow_none=True)
keyDistributor = xmlrpclib.ServerProxy("http://localhost:8001/", allow_none=True)
def readKey():
    f=open('key.pem','r')
    key=RSA.importKey(f.read())
    f.close()
    return key
def encryptAndEncode(plainText,pub_key):
    encrypted=pub_key.encrypt(plainText, 32)[0]
    return base64.b64encode(encrypted)
def decodeAndDecrypt(base64cipher,key):
     base64decoded=base64.b64decode(base64cipher)
     print ("Here")
     return key.decrypt(base64decoded)

def put(client_Put_Attest,block_Id,key_block_Version_No,new_Version_No,New_Hash,content,hashedSignedAttestation):
    global cloudStorage
    #client_Put_Attest=client_Put_Attest
    #block_Id=block_Id
    #key_block_Version_No=''
    #new_Version_No=new_Version_No
    #New_Hash=''
    #content=content
    #hashedSignedAttestation=''
    cloudStorage.put(client_Put_Attest,block_Id,key_block_Version_No,new_Version_No,New_Hash,content,hashedSignedAttestation)

def get(block_Id):
    global cloudStorage
    [block_Version,content,cloud_get_attestation]=cloudStorage.get(block_Id)
    return [block_Version,content,cloud_get_attestation]
   
pub_key=()
pri_key=()

#new_block_version='101'
user='u1'
block_id=1
#rw='w'
#user=raw_input("Enter user name u1,u2,u3?:")
#block_id=raw_input("Enter block ID:")
rw=raw_input("Read or Write?:")

pub_key=cPickle.loads(keyDistributor.getKey(1,'r',user))
#encryptedContent=encryptAndEncode("WAHEED ENCRYPTED",pub_key)
#put(block_id,block_version,encryptedContent)
if rw == 'w':
    pri_key=cPickle.loads(keyDistributor.getKey(1,'w',user))
    [block_version_no,cipherContent,cloud_get_attestation]=get(block_id)
    print ("Current Version:%s" %block_version_no)
    print ("Cipher:%s" %cipherContent)
    print ("Current Content:%s" %decodeAndDecrypt(cipherContent,pri_key))
    print ("Cloud Get Attestation:%s" %cloud_get_attestation)
    newContent=raw_input("Lets Modify content to?:")
    encryptedContent=encryptAndEncode(newContent,pub_key)
    put('client_put_attestation',block_id,' ',block_version_no+1,'new Hash',encryptedContent,'Hashed_signed_attestation')
    [block_version_no,cipherContent,cloud_get_attestation]=get(block_id)
    print ("Current Version:%s" %block_version_no)
    print ("Current Content:%s" %decodeAndDecrypt(cipherContent,pri_key))
    print ("Cloud Get Attestation:%s" %cloud_get_attestation)
else:
    put('client_put_attestation',1,' ',100,'new Hash',encryptAndEncode("Game of Thrones",pub_key),'Hashed_signed_attestation')
    put('client_put_attestation',2,' ',100,'new Hash',encryptAndEncode("Narcos",pub_key),'Hashed_signed_attestation')
    put('client_put_attestation',3,' ',100,'new Hash',encryptAndEncode("Breaking Bad",pub_key),'Hashed_signed_attestation')

    #put(1,100,encryptAndEncode("Game of Thrones",pub_key),"CPA")
    #put(2,100,encryptAndEncode("Narcos",pub_key),"CPA")
    #put(3,100,encryptAndEncode("Breaking Bad",pub_key),"CPA")
    #put(1,101,encryptAndEncode("Game of Thrones",pub_key),"CPA")

#print ("Decrypting data")
#for i in range(1,4):
#   print (get(i))
