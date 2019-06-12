import socket
import paramiko
import threading
import sys

# Using the key from Paramiko demo files (https://github.com/paramiko/paramiko/tree/master/demos)

host_key = paramiko.RSAKey(filename='test_rsa.key')

# http://docs.paramiko.org/en/2.4/api/server.html?highlight=ServerInterface
class Server(paramiko.ServerInterface): # Server class is INHERITING from paramiko.ServerInterface class.
    # This class defines an interface for controlling the behavior of Paramiko in server mode.
    def __init__(self):
        self.event = threading.Event()

    # Here, we will call the "check_channel_request" method of the "ServerInterface" Class.
    def check_channel_request(self, kind, chanid):  # CREATE CHANNELS
        if kind == 'session':
            return paramiko.OPEN_SUCCEEDED # exit code 0 (success)
        #otherwise
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_auth_password(self, username, password): # PERFORM AUTHENTICATION
        if (username == 'jose') and (password == 'qwaszx12'):
            return paramiko.AUTH_SUCCESSFUL
        #otherwise
        return paramiko.AUTH_FAILED

server = sys.argv[1]
ssh_port = int(sys.argv[2])

try:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1) # the SO_REUSEADDR flag tells the kernel to reuse
                                                                # a local socket in TIME_WAIT state, without waiting
                                                                    #  for its natural timeout to expire.
    sock.bind((server, ssh_port))
    sock.listen(100)
    print '[+] Listening for connection ...'
    client, addr = sock.accept()
except Exception, e:
    print '[-] Listen failed: ' + str(e)
    sys.exit(1)
else: # Only executed if there is no error (try block runs successfully)
    print '[+] Got a connection'


try:
    bhSession = paramiko.Transport(client) # Here we will try to encrypt the channel once the client connects to us (the server).
    '''
    An SSH Transport attaches to a stream (client socket above), negotiates an encrypted session, authenticates, and then creates stream tunnels, 
    called channels, across the session.
    '''
    bhSession.add_server_key(host_key) # When behaving as a server, the host key is used to sign certain packets during the SSH2 negotiation,
                                        #  so that the client can trust that we are who we say we are. Because this is used for signing,
                                            # the key must contain private key info, not just the public half
    # We create an object of type "Server" Class, which in turn, inherits from paramiko.ServerInterface class.
    server = Server()

    try:
        bhSession.start_server(server=server) # Negotiate a new SSH2 session as a server. This is the first step after creating a new Transport
                                                # and setting up your server host key(s). The 'server' parameter is an object used to perform
                                                   # authentication and create channels. After calling this method (or start_client or connect),
                                                    # you should no longer directly read from or write to the original socket object.
    except paramiko.SSHException, x:
        print '[-] SSH negotiation failed.'
    else: # On success
        chan = bhSession.accept(20) # Returns a new channel opened by the client over this Transport. If no channel is opened before the given timeout, None is returned
        print '[+] Authenticated!'
        print chan.recv(1024) # This is what received the "ClientConnected" string from the other script.
        chan.send('Welcome to bh_ssh')

        while True:
            try:
                command = raw_input("Enter command: ").strip('\n')
                if command != 'exit':
                    chan.send(command)
                    print chan.recv(1024) + '\n'
                else:
                    chan.send('exit')
                    print 'Exiting ...'
                    bhSession.close()
                    raise Exception ('exit')
            except KeyboardInterrupt:
                bhSession.close()
except Exception, e:
    print '[-] Caught exception: ' + str(e)

    try:
        bhSession.close()
    except:
        pass

    sys.exit(1)
