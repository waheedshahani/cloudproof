#!/usr/bin/env python

from Crypto.PublicKey import RSA
#from Crypto import Random

src_data = 'To be, or not to be - that is the question.'
print `src_data`

#random_generator = Random.new().read
#key = RSA.generate(1024, random_generator)
print 'Key generated'
#f=open('key.pem','w')
#f.write(key.exportKey('PEM'))
#f.close()


f=open('key.pem','r')
key=RSA.importKey(f.read())
f.close()
pub_key = key.publickey()
print 'Public key', pub_key

enc_data = pub_key.encrypt(src_data, 32)[0]
print `enc_data`

dec_data = key.decrypt(enc_data)
print `dec_data`

#publickey = key.exportKey('DER')
#privatekey = key.publickey().exportKey('DER')
#f=open('publicKey.pem','w')
#f.write(publickey)
#f.close()
#f=open('privateKey.pem','w')
#f.write(privatekey)
#f.close()

