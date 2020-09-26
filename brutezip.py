import zipfile
import struct

#Necessary constants. All original source is from "zipfile.py"
structFileHeader = "<4s2B4HL2L2H"
stringFileHeader = "PK\003\004"
sizeFileHeader = struct.calcsize(structFileHeader)
_FH_SIGNATURE = 0
_FH_FILENAME_LENGTH = 10
_FH_EXTRA_FIELD_LENGTH = 11
    
def prep(zip_path):
    """This is code that gets called every time you run extractall(), 
    but in reality only needs to be run once"""
    zf = zipfile.ZipFile(zip_path)
    check_bytes = []
    #We need the bytes and checkbyte for all files in the zip.
    #Checking just one could lead to false positives
    for packed in zf.namelist():
        zinfo = zf.getinfo(packed)
        with open(zip_path, 'rb') as zef_file:
            zef_file.seek(zinfo.header_offset, 0)
            fheader = zef_file.read(sizeFileHeader)
            if len(fheader) != sizeFileHeader:
                raise BadZipfile("Truncated file header")
            fheader = struct.unpack(structFileHeader, fheader)
            if fheader[_FH_SIGNATURE] != stringFileHeader:
                raise BadZipfile("Bad magic number for file header")
            fname = zef_file.read(fheader[_FH_FILENAME_LENGTH])
            if fheader[_FH_EXTRA_FIELD_LENGTH]:
                zef_file.read(fheader[_FH_EXTRA_FIELD_LENGTH])
            if fname != zinfo.orig_filename:
                raise BadZipfile, \
                        'File name in directory "%s" and header "%s" differ.' % (zinfo.orig_filename, fname)
            bytes = zef_file.read(12)
        #This is the magic here. 12 bytes plus the check_byte. Further explanation found in "zipfile.py"
        if zinfo.flag_bits & 0x8:
            check_bytes.append([bytes, (zinfo._raw_time >> 8) & 0xff])
        else:
            check_bytes.append([bytes, (zinfo.CRC >> 24) & 0xff])
    return check_bytes

def check_password(password, check_bytes):
    """Checks the password by comparing the check byte against what 
    ZipDecrypter says it should be"""
    #looping through all zipped files to avoid false positives
    for bytes, check_byte in check_bytes:
        zd = zipfile._ZipDecrypter(password)
        h = map(zd, bytes[0:12])
        if ord(h[11]) != check_byte:
            return False
    return True

def bruteforce(zip_path, alphabet, length, min):
    """Check provided options for bruteforcing. Characters, length, and 
    minimum length. Use itertools.product to generate wordlist and go!"""

    #Running "prep()" first to generate the check bytes
    check_bytes = prep(zip_path)
    for length in range(min,length+1):
        for pwd in itertools.product(alphabet, repeat=length):
            password = ''.join(pwd)
            if check_password(password, check_bytes):
                print("Password: {}".format(password))
                return password

if __name__ == '__main__':
    import sys
    import string
    zip_path = sys.argv[1]
    min = sys.argv[2]
    length = sys.argv[3]
    alphabet = string.ascii_letters + string.ascii_digits
    bruteforce(zip_path,alphabet,length,min)
