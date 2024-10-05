# A SIMPLE SSH Honeypot Project

This is a simple SSH honeypot that logs unauthorized access attempts, simulates a fake filesystem, and responds to limited shell commands. This project uses the `paramiko` library to create an SSH server that mimics a real server environment, allowing for security monitoring and experimentation.

## Features

- Customizable SSH banner and prompt
- Logging of connection attempts, credentials, and shell commands
- Fake filesystem to simulate directory navigation and file listing
- Custom command handling (e.g., `ls`, `pwd`, `whoami`)
- Multi-threaded to handle multiple connections

## Requirements

- Python 3.6+
- `paramiko` library for SSH handling
- `socket`, `threading`, and `logging` for server functionality

## Installation

1. Clone the repository:
    ```bash
    git clone https://github.com/Fruitpunch44/SIMPLE_SSH_HONEYPOT.git
    cd SSH_HONEYPOT
    ```


2. Generate SSH keys for the server (if not already generated):
    ```bash
    ssh-keygen -f id_rsa -N ''
    ```

3. Place the private key in the project directory.

## Usage

1. Run the server with:
    ```bash
    python SSH_HONEYPOT.py -H <host> -P <port>
    or within an ide argpase is already present if you wish to use the command line
    ```

2. Connect to the honeypot using an SSH client:
    ```bash
    ssh user@<host> -p <port>
    ```

### Example Commands

- `ls` - List files in the current directory
- `pwd` - Print the current directory path
- `cd` - Display message that directory change is not supported
- `whoami` - Display the current user
- `exit` - End the session

## Project Structure

- `SSH_HONEYPOT.py`: Main script to run the SSH honeypot
- `FakeFilesystem`: Class that simulates a simple filesystem with dummy directories and files
- `SSH_Server`: Custom SSH server class using `paramiko`

## Logging

- Logs are stored in `SSH_LOG/SSH_LOG.txt` by default
- Authentication attempts, connections, and command interactions are recorded

## Contributing

Contributions are welcome! Please open an issue or submit a pull request.

plan on adding more functionality later on
