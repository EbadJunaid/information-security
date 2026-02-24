from flask import Flask, request, jsonify
import uuid

app = Flask(__name__)

users = {}
sessions = {}
messages = []

@app.route("/register", methods=["POST"])
def register():
    data = request.json
    username = data.get("username")
    password = data.get("password")
    public_key = data.get("public_key")

    if username in users:
        return jsonify({"error": "User exists"}), 400

    users[username] = {
        "password": password,
        "public_key": public_key
    }

    return jsonify({"status": "registered"}), 200

@app.route("/login", methods=["POST"])
def login():
    data = request.json
    username = data.get("username")
    password = data.get("password")

    user = users.get(username)
    if not user or user["password"] != password:
        return jsonify({"error": "Invalid credentials"}), 401

    token = str(uuid.uuid4())
    sessions[token] = username

    return jsonify({"session_token": token}), 200

@app.route("/send", methods=["POST"])
def send_message():
    token = request.headers.get("Authorization")
    sender = sessions.get(token)

    if not sender:
        return jsonify({"error": "Unauthorized"}), 401

    data = request.json
    messages.append({
        "sender": sender,
        "recipient": data["to"],
        "encrypted_key": data["encrypted_key"],
        "ciphertext": data["ciphertext"],
        "nonce": data["nonce"],
        "tag": data["tag"]
    })

    return jsonify({"status": "message stored"}), 200

@app.route("/messages", methods=["GET"])
def fetch_messages():
    token = request.headers.get("Authorization")
    user = sessions.get(token)

    if not user:
        return jsonify({"error": "Unauthorized"}), 401

    user_messages = [m for m in messages if m["recipient"] == user]

    return jsonify(user_messages), 200

@app.route("/public_key/<username>", methods=["GET"])
def get_public_key(username):
    user = users.get(username)
    if not user:
        return jsonify({"error": "User not found"}), 404

    return jsonify({"public_key": user["public_key"]}), 200

if __name__ == "__main__":
    app.run(debug=True)