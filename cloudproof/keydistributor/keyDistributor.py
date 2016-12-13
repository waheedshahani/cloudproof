#!/usr/bin/env python
import os
import base64
import cPickle
import xmlrpclib
from SimpleXMLRPCServer import SimpleXMLRPCServer
from Crypto.PublicKey import RSA
from Crypto import Random
#This code generates keys (public & private) for each block. 
totalKeysNeeded=6
keyGenerateFlag=0
#src_data = 'To be, or not to be - that is the question.'
#print `src_data`
acl={0:{'r':['u1','u2','u3','cloud'],'w':['u1','u2','u3']},\
     1:{'r':['u2','u1','u3','cloud'],'w':['u1','u2']},\
     2:{'r':['u3','u1','u2','cloud'],'w':['u1','u3']},\
     3:{'r':['u4','u5','cloud'],'w':['u1','u4']},\
     4:{'r':['u5','u4','cloud'],'w':['u1','u5']},}
#Generating secret keys for CBC counter mode cryptography.
blockKeys={0:os.urandom(32),1:os.urandom(32),2:os.urandom(32),3:os.urandom(32),4:os.urandom(32),5:os.urandom(32)}
#This method receives any object and returns pickled version which can be serialized. 
#on receiver end this should be received using cPickle.loads and gives back object.....
def picklethis(object):
    with open('temp','w') as temp:
        cPickle.dump(object,temp)
    f=open('temp','r').read()
    return f
def unpicklethis(object):
    return cPickle.loads(object)
#This is secret key. any user with read access or write access can get this key. This is only used for en(de)crypting data.
def getSecretKey(block_Id,user):
     with open('temp','w') as temp:
        cPickle.dump(blockKeys[block_Id],temp)
     f=open('temp','r').read()
     return f

#This key pair is used signing and verification. private key is called signing key and public key is called verification key. 
def getSigningKey(block_Id,user):
     dict1= acl[block_Id]
     userList=dict1['w']
     if user not in userList:
         return 0
     f=open('%s.pri_key' %block_Id,'r').read()
     print ("Signing key %s.pri_key returned" %block_Id)
     return f
def getPublicKey(block_Id,user):
     dict1= acl[block_Id] #dict1 is dictionary
     #getting list of user for rw of particular block.
     userList=dict1['r']
     if user not in userList:
         print "**User not in list**"
         return 0
     f=open('%s.pub_key' %block_Id,'r').read()
     print ("Public key %s.pub_key returned" %block_Id)
     return f

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

