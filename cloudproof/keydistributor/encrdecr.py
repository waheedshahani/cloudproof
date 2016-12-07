#!/usr/bin/env python
import os
import base64
import cPickle
import xmlrpclib
from SimpleXMLRPCServer import SimpleXMLRPCServer
from Crypto.PublicKey import RSA
from Crypto import Random
#This code generates keys (public & private) for each block. 
totalKeysNeeded=5
keyGenerateFlag=0
#src_data = 'To be, or not to be - that is the question.'
#print `src_data`
acl={1:{'r':['u1','u2','u3'],'w':['u1']},\
     2:{'r':['u2','u1','u3'],'w':['u2']},\
     3:{'r':['u3','u1','u2'],'w':['u3']},\
     4:{'r':['u4','u5'],'w':['u4']},\
     5:{'r':['u5','u4'],'w':['u5']},}
#Generating secret keys for CBC counter mode cryptography.
blockKeys={1:os.urandom(32),2:os.urandom(32),3:os.urandom(32),4:os.urandom(32),5:os.urandom(32)}
#This is secret key. any user with read access or write access can get this key. This is only used for en(de)crypting data.
def getSecretKey(block_Id,user):
     with open('temp','w') as temp:
         cPickle.dump(blockKeys[1],temp)
     f=open('temp','r').read()
     return f

#This key pair is used signing and verification. private key is called signing key and public key is called verification key. 
def getSigningKey(block_Id,user):
     dict1= acl[block_Id]
     userList=dict1[rw]
     if user not in userList:
         return 0
     rsakey=RSA.importKey(f)
     f=open('%s.pri_key' %block_Id,'r').read()
     with open('temp','w') as temp:
         cPickle.dump(rsakey,temp)
     f=open('temp','r').read()
def getPublicKey(block_id,user):
     dict1= acl[block_Id] #dict1 is dictionary
     #getting list of user for rw of particular block.
     userList=dict1[rw]
     if user not in userList:
         return 0
     rsakey=RSA.importKey(f)
     f=open('%s.pri_key' %block_Id,'r').read()
     with open('temp','w') as temp:
         cPickle.dump(rsakey,temp)
     f=open('temp','r').read()


def getKey(block_Id,rw,user):
     dict1= acl[block_Id] #dict1 is dictionary
     #getting list of user for rw of particular block.
     userList=dict1[rw]
     if user not in userList:
         return 0
     if rw == 'r':
         f=open('%s.pub_key' %block_Id,'r').read()
     elif rw == 'w':
         f=open('%s.pri_key' %block_Id,'r').read() 
     rsakey=RSA.importKey(f)
     print rsakey
     #Converting object into character stream for serialization
     with open('temp','w') as temp:
         cPickle.dump(rsakey,temp) 
     f=open('temp','r').read()
#     print (f)
     #b64key=base64.b64encode(f)
     #f.close()
     #print rsakey
     return f     
#     return b64key


if keyGenerateFlag==1:
    for i in range (0,totalKeysNeeded):
        random_generator = Random.new().read
        key = RSA.generate(1024, random_generator)
        f=open('%d.pri_key' %i,'w')
        f.write(key.exportKey('PEM'))
        f.close()
        f=open('%d.pub_key' %i,'w')
        f.write(key.publickey().exportKey('PEM'))
    print ("Keys Generated")

keyServer=SimpleXMLRPCServer(("localhost", 8001), allow_none=True)
print ("Listening on port 8001...")
keyServer.register_function(getKey, "getKey")
keyServer.register_function(getSecretKey,"getSecretKey")
keyServer.register_function(getSigningKey,"getSigningKey")
keyServer.register_function(getPublicKey,"getPublicKey")
keyServer.serve_forever()


#f=open('key.pem','r')
#key=RSA.importKey(f.read())
#f.close()
#pub_key = key.publickey()
#print 'Public key', pub_key

#enc_data = pub_key.encrypt(src_data, 32)[0]
#print `enc_data`

#dec_data = key.decrypt(enc_data)
#print `dec_data`

#publickey = key.exportKey('DER')
#privatekey = key.publickey().exportKey('DER')
#f=open('publicKey.pem','w')
#f.write(publickey)
#f.close()
#f=open('privateKey.pem','w')
#f.write(privatekey)
#f.close()

