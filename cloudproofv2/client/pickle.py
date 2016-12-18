import cPickle
import os
def pickle(object):
    with open('temp','w') as temp:
        cPickle.dump(object,temp)
    f=open('temp','r').read()
    os.remove('temp')
    return f
def unpickle(object):
    return cPickle.loads(object)

