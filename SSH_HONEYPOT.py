import sys
import paramiko
import logging
import os
import threading
import socket
import argparse

'''
parser = argparse.ArgumentParser(description="SSH HoneyPot Project")

parser.add_argument('-H', '--Host', type=str, required=True, help="Specify the given host to run on")
parser.add_argument('-P', '--Port', type=int, required=True, help="Specify the given port number")

args = parser.parse_args()
'''
# set the host key/Port
try:
    HOST_KEY = paramiko.RSAKey(filename='id_rsa')
except paramiko.PasswordRequiredException as e:
    PASS = input('enter the rsa password: ')
    HOST_KEY = paramiko.RSAKey(filename='id_rsa', password=PASS)

port = 2200
host = '127.0.0.1'

# special keys at the beginning
UP_KEY = b'\x1b[A'  # Escape sequence for the up arrow key
DOWN_KEY = b'\x1b[B'  # Escape sequence for the down arrow key
LEFT_KEY = b'\x1b[D'  # Escape sequence for the left arrow key
RIGHT_KEY = b'\x1b[C'  # Escape sequence for the right arrow key
BACK_KEY = b'\x7f'  # Backspace key

# set loging file and directory
ssh_log_dir = 'SSH_LOG'
ssh_log_file = 'SSH_LOG.txt'

# create logging directory
log_path = os.path.join(ssh_log_dir, ssh_log_file)
if not os.path.exists(ssh_log_dir):
    os.mkdir(ssh_log_dir)

# setting the logging configurations
logging.basicConfig(filename=log_path, level=logging.INFO, format='%(asctime)s:'
                                                                  '%(filename)s,:'
                                                                  '%(levelname)s:'
                                                                  '%(message)s')


# custom error class
class Invalid_command(Exception):
    pass

# create Filesystem directory
class FakeFilesystem:
    def __init__(self):
        self.current_dir = "/home/user"
        self.filesystem = {
            ''/': ["etc", "var", "home", "boot", "tmp"],
            '/home': ["user"],
            '/home/user': ["Desktop", "Music", "Documents", "Downloads", ".ssh"],
            '/home/user/Desktop': ["2024_bank_invoice.txt", "Passport.jpg", "Server_manual.pdf"],
            '/home/user/Music': ["Linkin_park:Breaking_a_habit.mp3"],
            '/home/user/Documents': ["logs.txt", "notes.txt"],
            '/home/user/Downloads': ["Linuxbasicsforhackers.pdf", "important-notice.pdf", "server_utility_bills.pdf"],
            '/etc ': ["passwd", "shadow", "apache", "ssh", "nginx"],
            '/etc/passwd ': ["passwd", "shadow", "apache", "ssh", "nginx"],
            '/etc/passwd': [
                "root:x:0:0:root:/root:/bin/bash",
                "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin",
                "bin:x:2:2:bin:/bin:/usr/sbin/nologin",
                "sys:x:3:3:sys:/dev:/usr/sbin/nologin",
                "sync:x:4:65534:sync:/bin:/bin/sync",
                "games:x:5:60:games:/usr/games:/usr/sbin/nologin",
                "man:x:6:12:man:/var/cache/man:/usr/sbin/nologin",
                "lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin",
                "mail:x:8:8:mail:/var/mail:/usr/sbin/nologin",
                "news:x:9:9:news:/var/spool/news:/usr/sbin/nologin",
                "uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin",
                "nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin",
                "user:x:1000:1000::/home/user:/bin/bash"
            ],
            '/etc/shadow': [
                "root:$6$KJ8/7$Km5qJ9QPlJHGH8/OWoPzkJ/Sd3Jw1DnVFWpNEuQ.Tkc33eVJ93JkFZT6Lyvcsuy.PEXYLMh8jj4RmT2jSn9Hv/:19000:0:99999:7:::",
                "daemon:*:19000:0:99999:7:::",
                "bin:*:19000:0:99999:7:::",
                "sys:*:19000:0:99999:7:::",
                "sync:*:19000:0:99999:7:::",
                "games:*:19000:0:99999:7:::",
                "man:*:19000:0:99999:7:::",
                "lp:*:19000:0:99999:7:::",
                "mail:*:19000:0:99999:7:::",
                "news:*:19000:0:99999:7:::",
                "uucp:*:19000:0:99999:7:::",
                "nobody:*:19000:0:99999:7:::",
                "user:$6$randomsalt$Fk32jL3aFS0Ep9/PG1Gv7Nw8B7K4TZLQn8DsFp3hQTXoxK3wsfN/E$1ZmNP3cJnnV/:19000:0:99999:7:::"],
            '/etc/apache': ["apache_config", "apache_logs"],
            '/etc/ssh': ["sshd_config", "known_hosts", "ssh_host_rsa_key"],
            '/etc/nginx': ["nginx.conf", "mime.types", "conf.d"],
            '/home/user/.ssh': ["id_rsa", "id_rsa.pub", "known_hosts"],
            '/boot': ["System.map-6.8.11-amd64", "config-6.8.11-amd64 ", "initrd.img-6.8.11-amd64"],
            '/tmp': []
        }

    def get_current_dir(self):
        return self.current_dir

    def list_files(self):
        return self.filesystem.get(self.current_dir, [])


file_system = FakeFilesystem()


# create the server interface
class SSH_Server(paramiko.server.ServerInterface):
    def __init__(self):
        self.event = threading.Event()

    def check_channel_request(self, kind, chanid):
        if kind == 'session':
            return 0  # OPEN_SUCCEEDED

    def check_channel_shell_request(self, channel):
        self.event.set()
        return True

    def check_auth_password(self, username, password):
        if (username == 'Admin') and (password == '123456789'):
            logging.info(f'Authentication attempt with username:{username} and Password: {password} ')
        return 0

    def check_auth_publickey(self, username, key):
        pass

    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes):
        return True

    def get_banner(self):
        banner = 'SSH-2.0-MySSHServer_1.0'
        # important
        language = ''
        return banner, language


# handle cmd responses
def handle_cmd(cmd, chan):
    cmd = cmd.strip()

    if cmd == "ls":
        response = "\r\n".join(file_system.list_files())
        chan.send((response + '\r\n').encode())

    elif cmd == "pwd":
        response = "\r\n".join(file_system.get_current_dir())
        chan.send(response.encode())

    elif cmd == "cd":
        response = 'sorry i do not have that functions \r\n'
        chan.send(response.encode())

    elif cmd == "cmd":
        response = "sorry this is a linux system lol try again \r\n"
        chan.send(response.encode())

    elif cmd == 'whoami':
        response = 'user\r\n'
        chan.send(response.encode())

    elif cmd == "exit":
        response = 'Good bye\r\n'
        chan.send(response.encode())
        chan.close()
    else:
        chan.send('invalid command\r\n')


def handle_connection(client, addr):
    logging.info(f'new connection from {addr}')
    print(f'connection from {addr}')
    try:
        # create session object/add host keys/start server
        session = paramiko.Transport(client)
        session.add_server_key(HOST_KEY)
        server = SSH_Server()
        session.start_server(server=server)

        # create channel
        chan = session.accept(200)
        if chan is None:
            print(f'no channel')
            logging.error(f'no channel')
            sys.exit(1)
        chan.settimeout(100)

        print(f'{client} has been authenticated')
        logging.info(f'{client} has been authenticated')
        try:
            message = 'Welcome to Ubuntu 18.04.4 LTS (GNU/Linux 4.15.0-128-generic x86_64)\r\n\r\n'
            chan.send(message.encode())
            while True:
                chan.send(b"$: ")
                # create buffer to receive commands 
                command=b''
                # as long as no carraige return receive inputs
                while not command.endswith(b'\r'):
                    cmd=chan.recv(1024)
                    print(f'received {cmd}')
                    # Echo input to psuedo-simulate a basic terminal
                    if (
                            cmd != UP_KEY
                            and cmd != DOWN_KEY
                            and cmd != LEFT_KEY
                            and cmd != RIGHT_KEY
                            and cmd != BACK_KEY

                    ):
                        chan.send(cmd)
                        command +=cmd
                chan.send(b'\r\n')
                # decode the comand and pass on to the handle cmd func
                command = command.decode("utf-8").strip()
                logging.info(f'{command} received')
                
                # this is not effective just call the function directly instead of
                # using multiple threads
                '''chan_thread = threading.Thread(target=handle_cmd, args=(cmd,chan))
                chan_thread.start()'''
                
                handle_cmd(command, chan)

                server.event.wait(10)
                if not server.event.is_set():
                    logging.info(f'{client} never asked for a shell')
        except Exception as err:
            print(f'{err}')
    except paramiko.SSHException as e:
        print(f'could not start up ssh instance{e}')
        logging.warning(f'{e}')


# main function
def main():
    # Create the socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        # bind and listen for connection
        sock.bind((host, port))
        sock.listen(10)
        print(f'Listening for incoming connections on port {port} SSH on the address {host}')
    except Exception as error:
        logging.error(f'Error occurred while setting up the socket: {error}')

    threads = []  # Store the created threads

    try:
        while True:
            try:
                # Accept new client connections
                client_soc, client_addr = sock.accept()
                client_thread = threading.Thread(target=handle_connection, args=(client_soc, client_addr,))
                threads.append(client_thread)  # Keep track of the thread
                client_thread.start()  # Start the new thread
                logging.info(f'Connection established with {client_addr}')

            except Exception as err:
                logging.error(f'Error accepting connection: {err}')
    except KeyboardInterrupt:
        print("Server is shutting down.")
        logging.info("Server shutting down.")
        # Ensure all threads finish execution before exiting
        for thread in threads:
            thread.join()


if __name__ == '__main__':
    main()
