import argparse
import binascii
from sys import argv
import socket
import errno
import time

# check to see if there is string matching the key in the pairs.txt file
# if there is then send it back to the client

parser = argparse.ArgumentParser(description="""This is a very basic server program""")
parser.add_argument('-p', type=str, help='This is the pairs file', default='Pairs.txt', action='store',
                    dest='pairs_file')
parser.add_argument('port', type=int, help='This is the port to connect to the client on', action='store')
args = parser.parse_args(argv[1:])


""" We copied this method from the https://routley.io/posts/hand-writing-dns-messages/ website """
def send_udp_message(message, address, port):

    message = message.replace(" ", "").replace("\n", "")
    server_address = (address, port)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.sendto(binascii.unhexlify(message), server_address)
        data, _ = sock.recvfrom(4096)
    finally:
        sock.close()
    return binascii.hexlify(data).decode("utf-8")


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
        while True:
            data = csockid.recv(512)
            data = data.decode('utf-8')
            if len(data) == 0:
                break
            formatted_url = parse_string(data)

            message = "AA AA 01 00 00 01 00 00 00 00 00 00 " + formatted_url + " 00 00 01 00 01"

            response = send_udp_message(message, "8.8.8.8", 53)

            offset_length = len("aaaa818000010002000000000000010001") + len(formatted_url)
            rdLength = findRDLength(response)
            totalLength = rdLength
            finalListofIPs = ""
            response = response[offset_length:]
            for i in range(0, rdLength):
                type_msg = int(response[4:8], 16)
                length_skip = int(response[20:24], 16) * 2
                if type_msg == 1:
                    #A record
                    new_ip = response[24:32]
                    new_ip = parse_hex_ip(new_ip)
                    new_ip = new_ip[:len(new_ip) - 1]
                    finalListofIPs = finalListofIPs + new_ip + ","
                    response = response[24 + length_skip:]
                else:
                    #not A record
                    finalListofIPs = finalListofIPs + "OTHER,"
                    response = response[24+length_skip:]

            finalListofIPs = finalListofIPs[:-1]
            csockid.sendall(finalListofIPs.encode('utf-8'))
except IOError as e:
    if e.errno == errno.EPIPE:
        exit()

ss.close()
exit()
