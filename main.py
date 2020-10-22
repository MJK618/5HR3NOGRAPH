import base64
import os
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import numpy
from PIL import Image
import sys
import argparse
import os.path
from getpass import getpass


def derive_key(password, salt=None):
    if not salt:
        salt = os.urandom(16)
    kdf = PBKDF2HMAC(
         algorithm=hashes.SHA256(),
         length=32,
         salt=salt,
         iterations=100000,
         backend=default_backend()
     )

    return [base64.urlsafe_b64encode(kdf.derive(password)), salt]

def encrypt_info(password, info):
    ''' Receives a password and a byte array. Returns a Fernet token. '''
    password = bytes((password).encode('utf-8'))
    key, salt = derive_key(password)
    f = Fernet(key)
    token = f.encrypt(info)
    return bytes(salt) + bytes(token)

def decrypt_info(password, token, salt):
    ''' Receives a password and a Fernet token. Returns a byte array. '''
    password = bytes((password).encode('utf-8'))
    key = derive_key(password, salt)[0]
    f = Fernet(key)
    info = f.decrypt(token)
    return info
    

MAGIC_NUMBER = b'stegv3'

class HostElement:
    """ This class holds information about a host element. """
    def __init__(self, filename):
        self.filename = filename
        self.format = filename[-3:]
        self.header, self.data = get_file(filename)

    def save(self):
        self.filename = '_' + self.filename
        if self.format.lower() == 'wav':
            sound = numpy.concatenate((self.header, self.data))
            sound.tofile(self.filename)
        elif self.format.lower() == 'gif':
            gif = []
            for frame, palette in zip(self.data, self.header[0]):
                image = Image.fromarray(frame)
                image.putpalette(palette)
                gif.append(image)
            gif[0].save(self.filename, save_all=True, append_images = gif[1:], loop=0, duration=self.header[1])
        else:
            if not self.filename.lower().endswith(('png', 'bmp', 'webp')):
                print("Host has a lossy format and will be converted to PNG.")
                self.filename = self.filename[:-3] + 'png'
            image = Image.fromarray(self.data)
            image.save(self.filename, lossless=True, minimize_size=True, optimize=True)
        print("Information encoded in {}.".format(self.filename))

    def insert_message(self, message, bits=2, parasite_filename=None, password=None):
        raw_message_len = len(message).to_bytes(4, 'big')
        formatted_message = format_message(message, raw_message_len, parasite_filename)
        if password:
            formatted_message = encrypt_info(password, formatted_message)
        self.data = encode_message(self.data, formatted_message, bits)

    def read_message(self, password=None):
        msg = decode_message(self.data)
        
        if password:
            try:
                salt = bytes(msg[:16])
                msg = decrypt_info(password, bytes(msg[16:]), salt)
            except:
                print("Wrong password.")
                return

        check_magic_number(msg)
        msg_len = int.from_bytes(bytes(msg[6:10]), 'big')
        filename_len = int.from_bytes(bytes(msg[10:11]), 'big')

        start = filename_len + 11
        end = start + msg_len
        end_filename = filename_len + 11
        if(filename_len > 0):
            filename = '_' + bytes(msg[11:end_filename]).decode('utf-8')
        
        else:
            text = bytes(msg[start:end]).decode('utf-8')
            print(text)
            return

        with open(filename, 'wb') as f:
            f.write(bytes(msg[start:end]))

        print('File {} succesfully extracted from {}'.format(filename, self.filename))

    def free_space(self, bits=2):
        shape = self.data.shape
        self.data.shape = -1
        free = self.data.size * bits // 8
        self.data.shape = shape
        self.free = free
        return free

    def print_free_space(self, bits=2):
        free = self.free_space(bits)
        print('File: {}, free: (bytes) {:,}, encoding: 4 bit'.format(self.filename, free, bits))

def get_file(filename):
    ''' Returns data from file in a list with the header and raw data. '''
    if filename.lower().endswith('wav'):
        content = numpy.fromfile(filename, dtype=numpy.uint8)
        content = content[:10000], content[10000:]
    elif filename.lower().endswith('gif'):
        image = Image.open(filename)
        frames = []
        palettes = []
        try:
            while True:
                frames.append(numpy.array(image))
                palettes.append(image.getpalette())
                image.seek(image.tell()+1)
        except EOFError:
            pass
        content = [palettes, image.info['duration']], numpy.asarray(frames)
    else:
        image = Image.open(filename)
        if image.mode != 'RGB':
            image = image.convert('RGB')
        content = None, numpy.array(image)
    return content

def format_message(message, msg_len, filename=None):
    if not filename: # text
        message = MAGIC_NUMBER + msg_len + (0).to_bytes(1, 'big') + message
    else:
        filename = filename.encode('utf-8')
        filename_len = len(filename).to_bytes(1, 'big')
        message = MAGIC_NUMBER + msg_len + filename_len + filename + message
    return message;

def encode_message(host_data, message, bits):
    ''' Encodes the byte array in the image numpy array. '''
    shape = host_data.shape
    host_data.shape = -1, # convert to 1D
    uneven = 0
    divisor = 8 // bits

    print("Host dimension: {:,} bytes".format(host_data.size))
    print("Message size: {:,} bytes".format(len(message)))
    print("Maximum size: {:,} bytes".format(host_data.size // divisor))

    check_message_space(host_data.size // divisor, len(message))
 
    if(host_data.size % divisor != 0): # Hacky way to deal with pixel arrays that cannot be divided evenly
        uneven = 1
        original_size = host_data.size
        host_data = numpy.resize(host_data, host_data.size + (divisor - host_data.size % divisor))

    msg = numpy.zeros(len(host_data) // divisor, dtype=numpy.uint8)

    msg[:len(message)] = list(message)

    host_data[:divisor*len(message)] &= 256 - 2 ** bits # clear last bit(s)
    for i in range(divisor):
        host_data[i::divisor] |= msg >> bits*i & (2 ** bits - 1) # copy bits to host_data

    operand = (0 if (bits == 1) else (16 if (bits == 2) else 32))
    host_data[0] = (host_data[0] & 207) | operand # 5th and 6th bits = log_2(bits)

    if uneven:
        host_data = numpy.resize(host_data, original_size)
    
    host_data.shape = shape # restore the 3D shape
    
    return host_data

def check_message_space(max_message_len, message_len):
    ''' Checks if there's enough space to write the message. '''
    if(max_message_len < message_len):
        print('You have too few colors to store that message. Aborting.')
        exit(-1)
    else:
        print('Ok.')

def decode_message(host_data):
    ''' Decodes the image numpy array into a byte array. '''
    host_data.shape = -1, # convert to 1D
    bits = 2 ** ((host_data[0] & 48) >> 4) # bits = 2 ^ (5th and 6th bits)    
    divisor = 8 // bits

    if(host_data.size % divisor != 0):
        host_data = numpy.resize(host_data, host_data.size + (divisor - host_data.size % divisor))

    msg = numpy.zeros(len(host_data) // divisor, dtype=numpy.uint8)

    for i in range(divisor):
        msg |= (host_data[i::divisor] & (2 ** bits - 1)) << bits*i

    return msg

def check_magic_number(msg):
    if bytes(msg[0:6]) != MAGIC_NUMBER:
        print(bytes(msg[:6]))
        print('ERROR! No encoded info found!')
        exit(-1)
       
def main():
    parser = argparse.ArgumentParser(description='Simple steganography program based on the LSB method.')
    parser.add_argument('a', help='file or message to encode (if none, will read host)', nargs='*')
    parser.add_argument('b', help='host file')
    parser.add_argument('-p', '--password', help='set password to encrypt or decrypt a hidden file', action='store_true')
    parser.add_argument('-b', '--bits', help='number of bits per byte (default is 2)', nargs='?', default=2, choices=['1', '2', '4'])
    parser.add_argument('-c', '--check', help='check free space of argument files', action='store_true')
    args = parser.parse_args()
    bits = int(args.bits)
    
    if args.check:
        for arg in args.a + [args.b]:
            if os.path.isfile(arg):
                HostElement(arg).print_free_space(bits)
        return

    password = filename = None
    host_path = args.b
    host = HostElement(host_path)

    if args.a:
        args.a = args.a[0]
        if os.path.isfile(args.a):
            filename = args.a
            with open(filename, 'rb') as myfile:
                message = myfile.read()
        else:
            message = args.a.encode('utf-8')

        if args.password:
            while 1:
                password = getpass('Enter password (will not be echoed):')
                password_2 = getpass('Verify password (will not be echoed):')
                if password == password_2:
                    break
 
        host.insert_message(message, bits, filename, password)
        host.save()
    else:
       if args.password:
            password = getpass('Enter password (will not be echoed):')
       host.read_message(password)


if __name__ == '__main__':
    main()
    message = 'hello'.encode('utf-8') 
    
