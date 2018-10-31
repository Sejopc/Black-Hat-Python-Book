import socket
import threading 

bind_ip = "0.0.0.0"
bind_port = 9999

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

server.bind((bind_ip, bind_port))

server.listen(5) # 5 is the max amount of connections.

print("[*] Listening on %s:%d " % (bind_ip, bind_port))

# This is our client-handling threat
def handle_client(client_socket):

	#print out what the client sends to us (we are the server, remember...)
	request = client_socket.recv(1024) # buffer size o 1024

	print("[*] Received: %s " % request)

	#send back a packet
	client_socket.send("ACK!")
	client_socket.close()

while True:
	client, addr = server.accept() # As soon as a client connects, it accepts the requst
	# When a client connects, we receive the client socket into 'client' variable, and remote connection details
	# into 'addr' variable.

	print("[*] Accepted connection from %s:%d" %(addr[0], addr[1]))

	# spin up our client threat to handle incoming data
	client_handler = threading.Thread(target=handle_client, args=(client,))
	# Then we create a thread object that points to our handle_client function, and we pass it the client
	# socket object, as an argument (client)
	client_handler.start()

	