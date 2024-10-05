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
# set the host key/Port/Banner
try:
    HOST_KEY = paramiko.RSAKey(filename='id_rsa')
except paramiko.PasswordRequiredException as e:
    PASS = '12345678'
    HOST_KEY = paramiko.RSAKey(filename='id_rsa', password=PASS)

port = 2200
host = '192.168.0.138'

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
            '/': ["etc", "var", "home", "boot", "tmp"],
            '/home': ["user"],
            '/home/user': ["Desktop", "Music", "Documents", "Downloads", ".ssh"],
            '/home/user/Desktop': ["2024_bank_invoice.txt", "Passport.jpg", "Server_manual.pdf"],
            '/home/user/Music': ["Linkin_park:Breaking_a_habit.mp3"],
            '/home/user/Documents': ["logs.txt", "notes.txt"],
            '/home/user/Downloads': ["Linuxbasicsforhackers.pdf", "important-notice.pdf", "server_utility_bills.pdf"],
            '/etc ': ["passwd", "shadow", "apache", "ssh", "nginx"],
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
        if (username == 'Admin') and (password == '12345679'):
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
        response = "".join(file_system.list_files())
        chan.send(response.encode())

    elif cmd == "pwd":
        response = file_system.get_current_dir()
        chan.send(response.encode())

    elif cmd == "cd":
        response = 'sorry i do not have that functions'
        chan.send(response.encode())

    elif cmd == "cmd":
        response = "sorry this is a linux system lol try again"
        chan.send(response.encode())
        logging.info('received the cd ')
        raise Invalid_command("invalid command inputted ")

    elif cmd == 'whoami':
        response = 'user'
        chan.send(response.encode())

    elif cmd == "exit":
        response = 'Good bye'
        chan.send(response.encode())
        chan.close()
    else:
        chan.send('invalid command\n')


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
                cmd=chan.recv(1024).strip()
                print(f'{cmd}')
                if not cmd:
                    break
                cmd.decode()
                print(cmd)
                logging.info(f'{cmd} received')
                # this is not effective just call the function directly instead of
                # using multiple threads
                '''chan_thread = threading.Thread(target=handle_cmd, args=(cmd,chan))
                chan_thread.start()'''
                handle_cmd(cmd, chan)

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
