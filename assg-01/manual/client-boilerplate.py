import requests

SERVER = "http://127.0.0.1:5000"
session_token = None

def register(username, password):
    payload = {
        "username": username,
        "password": password,
        "public_key": "FAKE_PUBLIC_KEY"
    }
    r = requests.post(f"{SERVER}/register", json=payload)
    print(r.json())

def login(username, password):
    global session_token
    payload = {"username": username, "password": password}
    r = requests.post(f"{SERVER}/login", json=payload)
    data = r.json()
    session_token = data.get("session_token")
    print("Logged in. Token:", session_token)

def send_message(to, message):
    payload = {
        "to": to,
        "encrypted_key": "NOT_REAL_KEY",
        "ciphertext": message,
        "nonce": "NONE",
        "tag": "NONE"
    }
    headers = {"Authorization": session_token}
    r = requests.post(f"{SERVER}/send", json=payload, headers=headers)
    print(r.json())

def fetch_messages():
    headers = {"Authorization": session_token}
    r = requests.get(f"{SERVER}/messages", headers=headers)
    for msg in r.json():
        print("From:", msg["sender"])
        print("Message:", msg["ciphertext"])
        print("-----")

if __name__ == "__main__":
    print("== Simple Messaging Client ==")

    while True:
        cmd = input("register | login | send | inbox | quit: ")

        if cmd == "register":
            u = input("Username: ")
            p = input("Password: ")
            register(u, p)

        elif cmd == "login":
            u = input("Username: ")
            p = input("Password: ")
            login(u, p)

        elif cmd == "send":
            to = input("To: ")
            msg = input("Message: ")
            send_message(to, msg)

        elif cmd == "inbox":
            fetch_messages()

        elif cmd == "quit":
            break