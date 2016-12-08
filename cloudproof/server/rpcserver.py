import base64
import cPickle
import hashlib
import xmlrpclib
from SimpleXMLRPCServer import SimpleXMLRPCServer
#initializing 5 blocks with initial values as null
#storage={1:[],2:[],3:[],4:[],5:[]}
keyDistributor = xmlrpclib.ServerProxy("http://localhost:8001/", allow_none=True)
storage={}
cloud_get_attestation='This is cloud put attestation'

def put(client_Put_Attest,block_Id,key_block_Version_No,new_Version_No,New_Hash,content,hashedSignedAttestation,hashSign):
    print("BLOCK ID: %s" %block_Id)
#    print("Content: %s" %content)
    print("Key Block Version: %s" %new_Version_No)
    hash_object = hashlib.md5(content)
    if hashlib.md5(content).hexdigest() in New_Hash:
        print "Hashes match"
    print hashSign
    verifySignature(block_Id,content,hashSign)
    storage[block_Id]=[new_Version_No,content]
def get(block_Id):
    [block_Version_No,content]=storage[block_Id]
    return [block_Version_No,content,cloud_get_attestation]

def verifySignature(block_Id,encryptedEncodedContent,hashSign):
    global keyDistributor
    #First decoding and decrypting hashsign
    print  "Hash Sign:%s" %hashSign
    verificationKey=cPickle.loads(keyDistributor.getPublicKey(block_Id,'cloud'))
    print "here2"
    decrptb64Hash=verificationKey.decrypt(hashSign)
    print decrptb64Hash
#    b64=base64.b64decode(hashSign)
#    print b64   
#    print "Decoded hashsign %s" %str.decode(b64)
#    decrptb64Hash=verificationKey.decrypt(b64)
#    b64=base64.b64encode(decrptb64Hash)
#    print b64
    # calculating hashsign on content we received
#    contentHash=hashlib.md5(encryptedEncodedContent)
#    HexHash=contentHash.hexdigest()
#    b64new=base64.b64encode(hashSign)
#    print b64new
#    print "Here3"
#    if  b64 == b64new:
#        print "Integerity works"
#        return
 #   print "Integrity failed"
    
    
server = SimpleXMLRPCServer(("localhost", 8000), allow_none=True)
print ("Listening on port 8000...")
server.register_function(put, "put")
server.register_function(get, "get")
#server.register_function(getKey, "getKey")
server.serve_forever()
