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
	print("-e  --execute=file_to_run		- Execute the given file upon receiving a connection")
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
		opts, args = getopt.getopt(sys.argv[1:], "hle:t:p:cu:", ["help","listen","execute=", "target=", "port=", "command", "upload="])

	except getopt.GetoptError as err:	
		print(str(err))
		usage()

	for o,a in opts:
		if o in ("-h", "--help"):
			usage()
		elif o in ("-l", "--listen"):
			listen = True
		elif o in ("-e", "--execute"):
			execute = a
		elif o in ("-t", "--target"):
			target = a
		elif o in ("-p", "--port"):
			port = int(a)
		elif o in ("-c", "--command"):
			command = True
		elif o in ("-u", "--upload"):
			upload_destination = a
		else:
			assert False, "Unhandled Option"

		# are we going to listen or just send data from stdin?
		if not listen and len(target) and port > 0:

			# read in the buffer from the command line
			# this will block, so send Ctrl + D if not sending input
			# to stdin
			buffer = sys.stdin.read()

			#send data off
			client_sender(buffer)

		# are we going to listen (-l) and potentially upload things (-u), 
		# execute commands (-e), and drop a shell back (-c), 
		# depending on our command line options above.
		if listen:
			server_loop()

main()