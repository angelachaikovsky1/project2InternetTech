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


message = "AA AA 01 00 00 01 00 00 00 00 00 00 " \
          "07 65 78 61 6d 70 6c 65 03 63 6f 6d 00 00 01 00 01"

response = send_udp_message(message, "8.8.8.8", 53)
print(format_hex(response))

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
        while True:
            data = csockid.recv(512)
            data = data.decode('utf-8')
            found_key = 0
            for line in open(args.pairs_file, 'r'):
                # trim the line to avoid weird new line things
                line = line.strip()
                if data in line:
                    index = line.find(':')
                    offset = line.index(data) + len(data)
                    if offset == index:
                        found_key = 1
                        return_string = line[index + 1:]
                        csockid.sendall(return_string.encode('utf-8'))
            if found_key == 0:
                csockid.sendall("NOT FOUND".encode('utf-8'))

except IOError as e:
    if e.errno == errno.EPIPE:
        exit()

ss.close()
exit()
