import argparse
import binascii
from sys import argv
import socket
import errno

# check to see if there is string matching the key in the pairs.txt file
# if there is then send it back to the client

parser = argparse.ArgumentParser(description="""This is a very basic server program""")
parser.add_argument('-p', type=str, help='This is the pairs file', default='Pairs.txt', action='store',
                    dest='pairs_file')
parser.add_argument('port', type=int, help='This is the port to connect to the client on', action='store')
args = parser.parse_args(argv[1:])

"""
07 65 - 'example' has length 7, e
78 61 - x, a
6D 70 - m, p
6C 65 - l, e
03 63 - 'com' has length 3, c
6F 6D - o, m
00    - zero byte to end the QNAME
00 01 - QTYPE
00 01 - QCLASS

x = b'test'
x = binascii.hexlify(x)
y = str(x,'ascii')

print(x) # Outputs b'74657374' (hex encoding of "test")
print(y) # Outputs 74657374

x = b'test'
x = binascii.hexlify(x)
y = str(x,'ascii')

print(x) # Outputs b'74657374' (hex encoding of "test")
print(y) # Outputs 74657374
"""


# the goal is this:  93.184.216.34

def send_udp_message(message, address, port):
    """send_udp_message sends a message to UDP server

    message should be a hexadecimal encoded string
    """
    message = message.replace(" ", "").replace("\n", "")
    server_address = (address, port)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.sendto(binascii.unhexlify(message), server_address)
        data, _ = sock.recvfrom(4096)
    finally:
        sock.close()
    return binascii.hexlify(data).decode("utf-8")


def format_hex(hex):
    """format_hex returns a pretty version of a hex string"""
    octets = [hex[i:i + 2] for i in range(0, len(hex), 2)]
    pairs = [" ".join(octets[i:i + 2]) for i in range(0, len(octets), 2)]
    return "\n".join(pairs)


msg = "AA AA 01 00 00 01 00 00 00 00 00 00 " \
      "07 65 78 61 6d 70 6c 65 03 63 6f 6d 00 00 01 00 01"


def string_to_hex(section):
    len_str = hex(len(section))[2:]
    if len(len_str) == 1:
        len_str = '0' + len_str
   
    bit_str = section.encode('utf-8')
  
    bit_str = binascii.hexlify(bit_str)
    bit_str = str(bit_str, 'ascii')
    return len_str + bit_str


def parse_string(query):
    return_string = ""
    array = query.split('.')

    for value in array:
        return_string = return_string + string_to_hex(value)
    return return_string


def parse_hex_ip(ip):
   #ip = hex(ip)
   #ip = ip[2:]
    count = 4  # three periods
    return_string = ""
    while count > 0:
        i = 0
        temp_string = ""
        for i in range(0, 2):
            temp_string = temp_string + ip[0]
            ip = ip[1:]
        return_string = return_string + str(int(temp_string, 16))
        return_string = return_string + '.'
        count = count - 1

    return return_string


def findRDLength(response):
    rdLength = response[12:16]
    return int(rdLength)


try:
    ss = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
except socket.error as err:
    exit()

server_addr = ('', args.port)
ss.bind(server_addr)
ss.listen(1)
csockid, addr = ss.accept()

try:
    with csockid:
        #while True:
        data = csockid.recv(512)
        data = data.decode('utf-8')
        formatted_url = parse_string(data)
            #formatted_url = formatted_url[2:]
        message = "AA AA 01 00 00 01 00 00 00 00 00 00 " + formatted_url + " 00 00 01 00 01"
        print(formatted_url)  
        response = send_udp_message(message, "8.8.8.8", 53)
        print(response)
        rdLength = findRDLength(response)
        totalLength = rdLength*8
        finalListofIPs = ""
        while totalLength>0:
            ip = response[-8:]
            response = response[0:-8]
            new_ip = parse_hex_ip(ip)
            new_ip = new_ip[:len(new_ip) - 1]
            print(new_ip)
            finalListofIPs = new_ip + "," + finalListofIPs
            totalLength = totalLength - 8
        finalListofIPs = finalListofIPs[:-1]
        csockid.sendall(finalListofIPs.encode('utf-8'))
except IOError as e:
    if e.errno == errno.EPIPE:
        exit()

ss.close()
exit()

# create function that (for example takes the string www.example.come)
# and parses by '.' and calls another function
# which will return a string in hex composed of --> length + ascii encoding

