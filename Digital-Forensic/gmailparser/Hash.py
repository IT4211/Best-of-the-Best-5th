import hashlib

def get_hash(self):

    file = self.path + self.file
    data = open(file, "rb") # hash target file open
    bindata = data.read()   # hash target file read
    self.md5hash = hashlib.md5(bindata).hexdigest() # get md5 hash
    self.sha1hash = hashlib.sha1(bindata).hexdigest()   # get sha1 hash
    data.close()