#!/usr/bin/env python
import os
import base64
import pickle as p
import xmlrpclib
from SimpleXMLRPCServer import SimpleXMLRPCServer
from Crypto.PublicKey import RSA
from Crypto import Random
#This code generates keys (public & private) for each block. 
totalKeysNeeded=6
keyGenerateFlag=0
cloudGetAttestations={}
CloudPutAttestations={}
ClientPutAttestations={}
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

def DoesWSViolate(): # runs write serializibility checks on all CloudPutAttestations stored so far
    for block_Id, block_Data in CloudPutAttestations.iteritems():
        if not block_Id == 1:
            continue
        else:
            for block_Version_No, versionData in block_Data.iteritems():
                if len(versionData)!=3:
	              	print ("We got multiple cloud put attestations for  ID:%s version%s .Hence write serializibility violated." %(block_Id,block_Version_No))
                else:
    		        print ("Write serializibility intact for ID:%s version%s" %(block_Id,block_Version_No))
#	    ref=0
#            print "ID:%s version%s list length:%s Hash%s New_Hash%s" %(block_Id,block_Version,len(versionData),versionData[ref],versionData[ref+1])
#            ref=ref+5
def hasAccess(block_Id,user,accessType):
    dict1= acl[block_Id]
    userList=dict1[accessType]
    if user not in userList:
        return 0
    else:
        return 1
#This is secret key. any user with read access or write access can get this key. This is only used for en(de)crypting data.
def getSecretKey(block_Id,user):
     return p.pickle(blockKeys[block_Id])

#This key pair is used for signing and verification. private key is called signing key and public key is called verification key. 
def getSigningKey(block_Id,user):
     dict1= acl[block_Id]
     userList=dict1['w']
     if user not in userList:
         return 0
     f=open('%s.pri_key' %block_Id,'r').read()
#     print ("Signing key %s.pri_key returned" %block_Id)
     return f
def getPublicKey(block_Id,user):
     dict1= acl[block_Id] #dict1 is dictionary
     #getting list of user for rw of particular block.
     userList=dict1['r']
     if user not in userList:
         print "**User not in list**"
         return 0
     f=open('%s.pub_key' %block_Id,'r').read()
#     print ("Public key %s.pub_key returned" %block_Id)
     return f

def putAttestations(user,attestationType,block_Id,block_Version_No,attestation,key_block_Version_NoPickled,block_hash):
    print ("User:%s BlockID:%s Version:%s Type:%s" %(user,block_Id,block_Version_No,attestationType))
#    block_hash='block hash for version %s dummy' %block_Version_No
#    chain_hash='chain hash for version %s dummy' %block_Version_No
    if attestationType.lower() == "cloudputattestation":
        dict1={}
        list1=[]
        if CloudPutAttestations.has_key(block_Id):
            dict1=CloudPutAttestations[block_Id]
            if dict1.has_key(block_Version_No):
                list1=dict1[block_Version_No]
                list1.extend([block_hash,attestation,key_block_Version_NoPickled])
                dict1[block_Version_No]=list1
                CloudPutAttestations[block_Id]=dict1
            else:
                list1.extend([block_hash,attestation,key_block_Version_NoPickled])
                dict1[block_Version_No]=list1
                CloudPutAttestations[block_Id]=dict1
        else:
 #      	    print len(list1)
            list1.extend([block_hash,attestation,key_block_Version_NoPickled])
            dict1[block_Version_No]=list1
            CloudPutAttestations[block_Id]=dict1
        
  #     	print len(list1)
#        print ("%s received from %s" %(user,attestationType))
#    elif  attestationType.lower() == "cloudgetattestation":
#        print ("cloud get attestation received from %s" %user)
#    elif attestationType.lower() ==  "clientgetattestation":
#        print ("client get attestation received from %s" %user)

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

keyServer=SimpleXMLRPCServer(("localhost", 8001), allow_none=True,logRequests=False)
print ("Listening on port 8001...")
keyServer.register_function(getSecretKey,"getSecretKey")
keyServer.register_function(getSigningKey,"getSigningKey")
keyServer.register_function(getPublicKey,"getPublicKey")
keyServer.register_function(hasAccess,"hasAccess")
keyServer.register_function(putAttestations,"putAttestations")
keyServer.register_function(DoesWSViolate,"DoesWSViolate")
keyServer.serve_forever()


