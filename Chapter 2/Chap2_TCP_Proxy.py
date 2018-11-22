import sys
import socket
import threading

def server_loop(local_host, local_port, remote_host, remote_port, receive_first):

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    try:

        server.bind((local_host, local_port))

    except:

        print "[!!] Failed to listen on %s:%d" % (local_host, local_port)
        print "[!!] Check for other listening sockets or correct permissions."
        sys.exit(0)

    print "Listening on %s:%d" % (local_host, local_port)

    server.listen(5)

    while True:

        client_socket, addr = server.accept()

        # print out the local connection information
        print "[==>] Received incoming connection from %s:%d" % (addr[0], addr[1])

        # start a threat to talk to the remote host (the client that connected to us)
        proxy_thread = threading.Thread(target=proxy_handler, args=(client_socket, remote_host, remote_port, receive_first))
        proxy_thread.start()

def main():

    # no fancy command line parsing here
    if len(sys.argv[1:]) != 5:
        print "Usage: ./Chap2_TCP_Proxy.py [localhost] [localport] [remotehost] [remoteport] [receive_first]"
        print "Example: ./Chap2_TCP_Proxy.py 127.0.0.1 9000 10.12.132.1 9000 True"
        sys.exit(0)

    # set up local listening parameters
    local_host = sys.argv[1]
    local_port = int(sys.argv[2])

    # set up remote target
    remote_host = sys.argv[3] # Remote end-point
    remote_port = int(sys.argv[4])

    # this tell our proxy to connect and receive data before sending to the remote host (the client that connected to us)
    receive_first = sys.argv[5]

    if "True" in receive_first:
        receive_first = True
    else:
        receive_first = False

    # now spin our listening socket
    server_loop(local_host, local_port, remote_host, remote_port, receive_first)

def proxy_handler(client_socket, remote_host, remote_port, receive_first):

    # stream:
    # Client (remote host and port) --> our TCP Proxy Server --> Remote End-point.

    # connect to the remote end point
    remote_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    remote_socket.connect((remote_host, remote_port))

    # receive data from the remote end if necessary.
    if receive_first:

        remote_buffer = receive_from(remote_socket)
        hexdump(remote_buffer)

        # send it to our response handler
        remote_buffer = response_handler(remote_buffer) # perform packet modifications before sending them to localhost (client connected to us)

        # if we have data to send to our client, send it
        if len(remote_buffer):
            print "[<==] Sending %d bytes to localhost (client)." % len(remote_buffer)
            client_socket.send(remote_buffer)

    # now lets loop and read from local, send to remote, send to local.
    # rinse, wash, repeat
    while True:

        # read from client (connecting to localhost in our server machine)
        local_buffer = receive_from(client_socket)

        if len(local_buffer):

            print "[==>] Received %d bytes from localhost (client)." % len(local_buffer)
            hexdump(local_buffer)

            # send it to our request handler
            local_buffer = request_handler(local_buffer)

            # send off the data to the remote end-point
            remote_socket.send(local_buffer)
            print "[==>] Sent to remote."

            # receive back the response
            remote_buffer = receive_from(remote_socket)

            if len(remote_buffer):

                print "[<==] Received %d bytes from remote" % len(remote_buffer)
                hexdump(remote_buffer)

                # send to our response handler
                remote_buffer = response_handler(remote_buffer)

                # send the response to the local socket (client)
                client_socket.send(remote_buffer)

                print "[<==] Sent to localhost."

        # if no more data on either side, close the connections
        if not len(local_buffer) or not len(remote_buffer):
            client_socket.close()
            remote_socket.close()
            print "[*] No more data. Closing connections."

            break # Break from the while loop, and hence, the function itself.

# this is a pretty hex dumping function directly taken from the comments here:
# http://code.activestate.com/recipes/142812-hex-dumper/
def hexdump(src, length=16):
    result = []
    digits = 4 if isinstance(src, unicode) else 2

    for i in xrange(0, len(src), length):
        s = src[i:i+length] # will grab in chunks of 16 bits (or bytes?).
        hexa = b' '.join(["%0*X" % (digits, ord(x)) for x in s]) # %x/%X - Integers in hex representation (lowercase/uppercase).
                                                                # Links to understand it's behavior, at the end of the program.
        text = b''.join([x if 0x20 <= ord(x) < 0x7F else b'.' for x in s]) # Don't really understand it.
        result.append( b"%04X   %-*s    %s" % (i, length*(digits+1), hexa, text))

        print b'\n'.join(result)


def receive_from(connection):

    buffer = ""

    # We set a 2 seconds timeout; depending on your target, this may need to be adjusted.
    connection.settimeout(2)

    try:

        # keep reading into the buffer until there's no more data, or we timeout.
        while True:

            data = connection.recv(4096)

            if not data: # if there's no more data, break  from the While loop.
                break

            buffer += data
    except:
        #print("No data received, or timeout reached.")
        pass

    return buffer

# modify any requests destined to the remote end host
def request_handler(buffer):
    # perform packet modifications
    return buffer

# modify any requests destined to the local (client) host.
def response_handler(buffer):
    # perform packet modifications
    return buffer


main()

'''
Took me long to understood hexdump function. Just read the following links:

https://www.programiz.com/python-programming/methods/string/join
https://www.geeksforgeeks.org/ord-function-python/
https://www.learnpython.org/en/String_Formatting
https://stackoverflow.com/questions/5661725/format-ints-into-string-of-hex

https://www.rapidtables.com/convert/number/decimal-to-hex.html
https://unicode-table.com/en/#0046

So what the ord() function does it convert the string character (could be a number within " ") into the Unicode Decimal Representation.
For letter 'F' for example, it will be 70, which converted to HEX is 46 (or 0046 since we using 4 digits, padding with 0). The padding is done
by the "%0*X" % (digits, ord(x)) part. %x or %X converts Integers to HEX representation, that's why 70 turns into 0046.

Simple test:

>>> b' '.join(['%0*X' %(4,ord(i)) for i in "Isma se la come"])
'0049 0073 006D 0061 0020 0073 0065 0020 006C 0061 0020 0063 006F 006D 0065'

The b' ' means Bytes concatenation, but even if we don't use the 'b' letter, it still works.
'''