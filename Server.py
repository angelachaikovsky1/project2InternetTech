import argparse
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