from flask import Flask, request, jsonify, Response
import os
import json
import binascii
from datetime import datetime, timezone

from Crypto.Cipher import AES

from google.protobuf import descriptor_pb2
from google.protobuf import descriptor_pool
from google.protobuf import message_factory

import firebase_admin
from firebase_admin import credentials, db

app = Flask(__name__)

SERVICE_ACCOUNT_KEY = os.environ["FIREBASE_SERVICE_ACCOUNT_KEY"]
DATABASE_URL = os.environ["FIREBASE_RTDB_URL"]

AES_KEY = os.environ["AES_KEY"].encode("latin1")
AES_IV  = os.environ["AES_IV"].encode("latin1")

cred_dict = json.loads(SERVICE_ACCOUNT_KEY)
cred = credentials.Certificate(cred_dict)
firebase_admin.initialize_app(cred, {"databaseURL": DATABASE_URL})

def build_proto_messages():
    fdp = descriptor_pb2.FileDescriptorProto()
    fdp.name = "majorregister.proto"
    fdp.package = ""

    mr = fdp.message_type.add()
    mr.name = "MajorRegister"

    f = mr.field.add(); f.name = "nickname"; f.number = 1
    f.label = descriptor_pb2.FieldDescriptorProto.LABEL_OPTIONAL
    f.type = descriptor_pb2.FieldDescriptorProto.TYPE_STRING

    f = mr.field.add(); f.name = "access_token"; f.number = 2
    f.label = descriptor_pb2.FieldDescriptorProto.LABEL_OPTIONAL
    f.type = descriptor_pb2.FieldDescriptorProto.TYPE_STRING

    f = mr.field.add(); f.name = "open_id"; f.number = 3
    f.label = descriptor_pb2.FieldDescriptorProto.LABEL_OPTIONAL
    f.type = descriptor_pb2.FieldDescriptorProto.TYPE_STRING

    f = mr.field.add(); f.name = "platform"; f.number = 6
    f.label = descriptor_pb2.FieldDescriptorProto.LABEL_OPTIONAL
    f.type = descriptor_pb2.FieldDescriptorProto.TYPE_INT32

    f = mr.field.add(); f.name = "platform_register_info"; f.number = 14
    f.label = descriptor_pb2.FieldDescriptorProto.LABEL_OPTIONAL
    f.type = descriptor_pb2.FieldDescriptorProto.TYPE_BYTES

    f = mr.field.add(); f.name = "lang"; f.number = 15
    f.label = descriptor_pb2.FieldDescriptorProto.LABEL_OPTIONAL
    f.type = descriptor_pb2.FieldDescriptorProto.TYPE_STRING

    f = mr.field.add(); f.name = "client_type"; f.number = 16
    f.label = descriptor_pb2.FieldDescriptorProto.LABEL_OPTIONAL
    f.type = descriptor_pb2.FieldDescriptorProto.TYPE_INT32

    f = mr.field.add(); f.name = "uid"; f.number = 17
    f.label = descriptor_pb2.FieldDescriptorProto.LABEL_OPTIONAL
    f.type = descriptor_pb2.FieldDescriptorProto.TYPE_INT64

    resp = fdp.message_type.add()
    resp.name = "MajorRegisterResponse"
    fr = resp.field.add(); fr.name = "accountId"; fr.number = 3
    fr.label = descriptor_pb2.FieldDescriptorProto.LABEL_OPTIONAL
    fr.type = descriptor_pb2.FieldDescriptorProto.TYPE_INT64

    pool = descriptor_pool.DescriptorPool()
    pool.AddSerializedFile(fdp.SerializeToString())
    factory = message_factory.MessageFactory(pool)

    mr_desc = pool.FindMessageTypeByName("MajorRegister")
    resp_desc = pool.FindMessageTypeByName("MajorRegisterResponse")
    MajorRegister = factory.GetPrototype(mr_desc)
    MajorRegisterResponse = factory.GetPrototype(resp_desc)
    return MajorRegister, MajorRegisterResponse

MajorRegister, MajorRegisterResponse = build_proto_messages()

def pkcs7_unpad(data: bytes) -> bytes:
    if not data:
        return data
    pad_len = data[-1]
    if pad_len < 1 or pad_len > AES.block_size:
        raise ValueError("Invalid padding")
    if data[-pad_len:] != bytes([pad_len]) * pad_len:
        raise ValueError("Invalid PKCS7 padding")
    return data[:-pad_len]

def aes_cbc_decrypt(ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
    if len(key) not in (16, 24, 32):
        raise ValueError("AES key must be 16/24/32 bytes")
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = cipher.decrypt(ciphertext)
    return pkcs7_unpad(plaintext)

def xor_platform_check(open_id: str) -> bytes:
    encoded_open_id = open_id.encode("latin1")
    xor_key = [int(x, 16) for x in os.environ["XOR_KEY"].split(",")]
    if len(xor_key) < len(encoded_open_id):
        times = (len(encoded_open_id) + len(xor_key) - 1) // len(xor_key)
        xor_key = (bytes(xor_key) * times)[:len(encoded_open_id)]
    else:
        xor_key = bytes(xor_key[:len(encoded_open_id)])
    return bytes([d ^ m for d, m in zip(encoded_open_id, xor_key)])

@app.route("/MajorRegister", methods=["POST"])
def major_register():
    ciphertext = request.get_data()
    if not ciphertext:
        return jsonify({"error": "Empty request body"}), 400

    try:
        plaintext = aes_cbc_decrypt(ciphertext, AES_KEY, AES_IV)
    except Exception as e:
        return jsonify({"error": "AES decrypt failed", "detail": str(e)}), 400

    try:
        req = MajorRegister()
        req.ParseFromString(plaintext)
    except Exception as e:
        return jsonify({"error": "Protobuf parse failed", "detail": str(e)}), 400

    try:
        uid = int(getattr(req, "uid", 0) or 0)
    except Exception:
        return jsonify({"error": "Invalid uid value"}, 400)
    access_token = getattr(req, "access_token", "") or ""
    open_id = getattr(req, "open_id", "") or ""
    platform_register_info = getattr(req, "platform_register_info", b"") or b""
    nickname = getattr(req, "nickname", "") or ""
    platform = int(getattr(req, "platform", 0) or 0)
    lang = getattr(req, "lang", "") or ""
    client_type = int(getattr(req, "client_type", 0) or 0)

    if uid <= 0:
        return jsonify({"error": "Invalid uid in request"}), 400
    
    if len(nickname) > 16:
        return jsonify({"error": "Nickname cannot exceed 16 characters"}), 400

    tokens_ref = db.reference(f"guest/{uid}/tokens")
    stored = tokens_ref.get()
    if not stored:
        return jsonify({"error": "User tokens not found"}, 404), 404

    stored_access = stored.get("access_token")
    stored_open_id = stored.get("open_id")

    if stored_access is None or stored_open_id is None:
        return jsonify({"error": "Stored tokens incomplete"}, 403), 403

    if access_token != stored_access or open_id != stored_open_id:
        return jsonify({"error": "access_token or open_id mismatch"}, 403), 403

    try:
        expected = xor_platform_check(open_id)
    except Exception as e:
        return jsonify({"error": "XOR generation failed", "detail": str(e)}), 500

    if expected != platform_register_info:
        return jsonify({"error": "platform_register_info mismatch"}, 403), 403

    accountId = uid + 10000000

    now_iso = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    profile_data = {
        "nickname": nickname,
        "accountId": accountId,
        "platform": platform,
        "lang": lang,
        "client_type": client_type,
        "platform_register_info": binascii.hexlify(platform_register_info).decode(),
        "registered_at": now_iso,
    }

    try:
        db.reference(f"guest/{uid}/profile").set(profile_data)
        db.reference(f"guest/{uid}/accountId").set(accountId)
    except Exception as e:
        return jsonify({"error": "DB write failed", "detail": str(e)}), 500

    resp_msg = MajorRegisterResponse()
    resp_msg.accountId = int(accountId)
    resp_bytes = resp_msg.SerializeToString()
    resp_hex = binascii.hexlify(resp_bytes).decode()

    return Response(resp_hex, mimetype="text/plain")

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)