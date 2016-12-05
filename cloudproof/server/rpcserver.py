import hashlib
import xmlrpclib
from SimpleXMLRPCServer import SimpleXMLRPCServer
#initializing 5 blocks with initial values as null
#storage={1:[],2:[],3:[],4:[],5:[]}
storage={}
cloud_get_attestation='This is cloud put attestation'
def put(client_Put_Attest,block_Id,key_block_Version_No,new_Version_No,New_Hash,content,hashedSignedAttestation):
    print("BLOCK ID: %s" %block_Id)
#    print("Content: %s" %content)
    print("Key Block Version: %s" %new_Version_No)
    hash_object = hashlib.md5(content)
    print(hash_object.hexdigest())
    if hashlib.md5(content).hexdigest() in New_Hash:
        print "Hashes match"
    storage[block_Id]=[new_Version_No,content]
def get(block_Id):
    [block_Version_No,content]=storage[block_Id]
    return [block_Version_No,content,cloud_get_attestation]

server = SimpleXMLRPCServer(("localhost", 8000), allow_none=True)
print ("Listening on port 8000...")
server.register_function(put, "put")
server.register_function(get, "get")
#server.register_function(getKey, "getKey")
server.serve_forever()
