from flask import Flask, request, jsonify, Response
import os
import json
import binascii
import time
import sys
from datetime import datetime, timezone

from Crypto.Cipher import AES
import jwt

from google.protobuf import descriptor_pb2
from google.protobuf import descriptor_pool
from google.protobuf import message_factory

import firebase_admin
from firebase_admin import credentials, db

app = Flask(__name__)

SERVICE_ACCOUNT_KEY = os.environ["FIREBASE_SERVICE_ACCOUNT_KEY"]
DATABASE_URL = os.environ["FIREBASE_RTDB_URL"]
AES_KEY = os.environ["AES_KEY"].encode("latin1")
AES_IV = os.environ["AES_IV"].encode("latin1")
JWT_SECRET = os.environ["JWT_SECRET"]

if len(AES_IV) != AES.block_size:
    print(f"AES_IV must be {AES.block_size} bytes; got {len(AES_IV)}", file=sys.stderr)
    raise SystemExit(1)
if len(AES_KEY) not in (16, 24, 32):
    print(f"AES_KEY must be 16/24/32 bytes; got {len(AES_KEY)}", file=sys.stderr)
    raise SystemExit(1)

try:
    cred_dict = json.loads(SERVICE_ACCOUNT_KEY)
except Exception as e:
    print("Failed to parse FIREBASE_SERVICE_ACCOUNT_KEY JSON:", e, file=sys.stderr)
    raise SystemExit(1)

try:
    cred = credentials.Certificate(cred_dict)
    firebase_admin.initialize_app(cred, {"databaseURL": DATABASE_URL})
except Exception as e:
    print("Failed to initialize Firebase Admin SDK:", e, file=sys.stderr)
    raise SystemExit(1)

def build_majorregister_proto():
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

MajorRegister, MajorRegisterResponse = build_majorregister_proto()

def build_majorlogin_proto():
    fdp = descriptor_pb2.FileDescriptorProto()
    fdp.name = "majorlogin.proto"

    mr = fdp.message_type.add()
    mr.name = "MajorLogin"

    f = mr.field.add(); f.name = "uid"; f.number = 1
    f.label = descriptor_pb2.FieldDescriptorProto.LABEL_OPTIONAL
    f.type = descriptor_pb2.FieldDescriptorProto.TYPE_INT64

    f = mr.field.add(); f.name = "event_time"; f.number = 3
    f.label = descriptor_pb2.FieldDescriptorProto.LABEL_OPTIONAL
    f.type = descriptor_pb2.FieldDescriptorProto.TYPE_STRING

    f = mr.field.add(); f.name = "game_name"; f.number = 4
    f.label = descriptor_pb2.FieldDescriptorProto.LABEL_OPTIONAL
    f.type = descriptor_pb2.FieldDescriptorProto.TYPE_STRING

    f = mr.field.add(); f.name = "platform_id"; f.number = 5
    f.label = descriptor_pb2.FieldDescriptorProto.LABEL_OPTIONAL
    f.type = descriptor_pb2.FieldDescriptorProto.TYPE_INT32

    f = mr.field.add(); f.name = "client_version"; f.number = 7
    f.label = descriptor_pb2.FieldDescriptorProto.LABEL_OPTIONAL
    f.type = descriptor_pb2.FieldDescriptorProto.TYPE_STRING

    f = mr.field.add(); f.name = "system_software"; f.number = 8
    f.label = descriptor_pb2.FieldDescriptorProto.LABEL_OPTIONAL
    f.type = descriptor_pb2.FieldDescriptorProto.TYPE_STRING

    f = mr.field.add(); f.name = "system_hardware"; f.number = 9
    f.label = descriptor_pb2.FieldDescriptorProto.LABEL_OPTIONAL
    f.type = descriptor_pb2.FieldDescriptorProto.TYPE_STRING

    f = mr.field.add(); f.name = "telecom_operator"; f.number = 10
    f.label = descriptor_pb2.FieldDescriptorProto.LABEL_OPTIONAL
    f.type = descriptor_pb2.FieldDescriptorProto.TYPE_STRING

    f = mr.field.add(); f.name = "network_type"; f.number = 11
    f.label = descriptor_pb2.FieldDescriptorProto.LABEL_OPTIONAL
    f.type = descriptor_pb2.FieldDescriptorProto.TYPE_STRING

    f = mr.field.add(); f.name = "screen_width"; f.number = 12
    f.label = descriptor_pb2.FieldDescriptorProto.LABEL_OPTIONAL
    f.type = descriptor_pb2.FieldDescriptorProto.TYPE_INT32

    f = mr.field.add(); f.name = "screen_height"; f.number = 13
    f.label = descriptor_pb2.FieldDescriptorProto.LABEL_OPTIONAL
    f.type = descriptor_pb2.FieldDescriptorProto.TYPE_INT32

    f = mr.field.add(); f.name = "screen_dpi"; f.number = 14
    f.label = descriptor_pb2.FieldDescriptorProto.LABEL_OPTIONAL
    f.type = descriptor_pb2.FieldDescriptorProto.TYPE_STRING

    f = mr.field.add(); f.name = "processor_details"; f.number = 15
    f.label = descriptor_pb2.FieldDescriptorProto.LABEL_OPTIONAL
    f.type = descriptor_pb2.FieldDescriptorProto.TYPE_STRING

    f = mr.field.add(); f.name = "memory"; f.number = 16
    f.label = descriptor_pb2.FieldDescriptorProto.LABEL_OPTIONAL
    f.type = descriptor_pb2.FieldDescriptorProto.TYPE_INT32

    f = mr.field.add(); f.name = "gpu_renderer"; f.number = 17
    f.label = descriptor_pb2.FieldDescriptorProto.LABEL_OPTIONAL
    f.type = descriptor_pb2.FieldDescriptorProto.TYPE_STRING

    f = mr.field.add(); f.name = "gpu_version"; f.number = 18
    f.label = descriptor_pb2.FieldDescriptorProto.LABEL_OPTIONAL
    f.type = descriptor_pb2.FieldDescriptorProto.TYPE_STRING

    f = mr.field.add(); f.name = "unique_device_id"; f.number = 19
    f.label = descriptor_pb2.FieldDescriptorProto.LABEL_OPTIONAL
    f.type = descriptor_pb2.FieldDescriptorProto.TYPE_STRING

    f = mr.field.add(); f.name = "client_ip"; f.number = 20
    f.label = descriptor_pb2.FieldDescriptorProto.LABEL_OPTIONAL
    f.type = descriptor_pb2.FieldDescriptorProto.TYPE_STRING

    f = mr.field.add(); f.name = "language"; f.number = 21
    f.label = descriptor_pb2.FieldDescriptorProto.LABEL_OPTIONAL
    f.type = descriptor_pb2.FieldDescriptorProto.TYPE_STRING

    f = mr.field.add(); f.name = "open_id"; f.number = 22
    f.label = descriptor_pb2.FieldDescriptorProto.LABEL_OPTIONAL
    f.type = descriptor_pb2.FieldDescriptorProto.TYPE_STRING

    f = mr.field.add(); f.name = "open_id_type"; f.number = 23
    f.label = descriptor_pb2.FieldDescriptorProto.LABEL_OPTIONAL
    f.type = descriptor_pb2.FieldDescriptorProto.TYPE_STRING

    f = mr.field.add(); f.name = "device_type"; f.number = 24
    f.label = descriptor_pb2.FieldDescriptorProto.LABEL_OPTIONAL
    f.type = descriptor_pb2.FieldDescriptorProto.TYPE_STRING

    f = mr.field.add(); f.name = "device_model"; f.number = 25
    f.label = descriptor_pb2.FieldDescriptorProto.LABEL_OPTIONAL
    f.type = descriptor_pb2.FieldDescriptorProto.TYPE_STRING

    f = mr.field.add(); f.name = "access_token"; f.number = 29
    f.label = descriptor_pb2.FieldDescriptorProto.LABEL_OPTIONAL
    f.type = descriptor_pb2.FieldDescriptorProto.TYPE_STRING

    f = mr.field.add(); f.name = "platform_sdk_id"; f.number = 30
    f.label = descriptor_pb2.FieldDescriptorProto.LABEL_OPTIONAL
    f.type = descriptor_pb2.FieldDescriptorProto.TYPE_INT32

    f = mr.field.add(); f.name = "network_operator_a"; f.number = 41
    f.label = descriptor_pb2.FieldDescriptorProto.LABEL_OPTIONAL
    f.type = descriptor_pb2.FieldDescriptorProto.TYPE_STRING

    f = mr.field.add(); f.name = "network_type_a"; f.number = 42
    f.label = descriptor_pb2.FieldDescriptorProto.LABEL_OPTIONAL
    f.type = descriptor_pb2.FieldDescriptorProto.TYPE_STRING

    f = mr.field.add(); f.name = "client_using_version"; f.number = 57
    f.label = descriptor_pb2.FieldDescriptorProto.LABEL_OPTIONAL
    f.type = descriptor_pb2.FieldDescriptorProto.TYPE_STRING

    f = mr.field.add(); f.name = "external_storage_total"; f.number = 60
    f.label = descriptor_pb2.FieldDescriptorProto.LABEL_OPTIONAL
    f.type = descriptor_pb2.FieldDescriptorProto.TYPE_INT32

    f = mr.field.add(); f.name = "external_storage_available"; f.number = 61
    f.label = descriptor_pb2.FieldDescriptorProto.LABEL_OPTIONAL
    f.type = descriptor_pb2.FieldDescriptorProto.TYPE_INT32

    f = mr.field.add(); f.name = "internal_storage_total"; f.number = 62
    f.label = descriptor_pb2.FieldDescriptorProto.LABEL_OPTIONAL
    f.type = descriptor_pb2.FieldDescriptorProto.TYPE_INT32

    f = mr.field.add(); f.name = "internal_storage_available"; f.number = 63
    f.label = descriptor_pb2.FieldDescriptorProto.LABEL_OPTIONAL
    f.type = descriptor_pb2.FieldDescriptorProto.TYPE_INT32

    f = mr.field.add(); f.name = "game_disk_storage_available"; f.number = 64
    f.label = descriptor_pb2.FieldDescriptorProto.LABEL_OPTIONAL
    f.type = descriptor_pb2.FieldDescriptorProto.TYPE_INT32

    f = mr.field.add(); f.name = "game_disk_storage_total"; f.number = 65
    f.label = descriptor_pb2.FieldDescriptorProto.LABEL_OPTIONAL
    f.type = descriptor_pb2.FieldDescriptorProto.TYPE_INT32

    f = mr.field.add(); f.name = "external_sdcard_avail_storage"; f.number = 66
    f.label = descriptor_pb2.FieldDescriptorProto.LABEL_OPTIONAL
    f.type = descriptor_pb2.FieldDescriptorProto.TYPE_INT32

    f = mr.field.add(); f.name = "external_sdcard_total_storage"; f.number = 67
    f.label = descriptor_pb2.FieldDescriptorProto.LABEL_OPTIONAL
    f.type = descriptor_pb2.FieldDescriptorProto.TYPE_INT32

    f = mr.field.add(); f.name = "login_by"; f.number = 73
    f.label = descriptor_pb2.FieldDescriptorProto.LABEL_OPTIONAL
    f.type = descriptor_pb2.FieldDescriptorProto.TYPE_INT32

    f = mr.field.add(); f.name = "library_path"; f.number = 74
    f.label = descriptor_pb2.FieldDescriptorProto.LABEL_OPTIONAL
    f.type = descriptor_pb2.FieldDescriptorProto.TYPE_STRING

    f = mr.field.add(); f.name = "cpu_type"; f.number = 76
    f.label = descriptor_pb2.FieldDescriptorProto.LABEL_OPTIONAL
    f.type = descriptor_pb2.FieldDescriptorProto.TYPE_INT32

    f = mr.field.add(); f.name = "library_token"; f.number = 77
    f.label = descriptor_pb2.FieldDescriptorProto.LABEL_OPTIONAL
    f.type = descriptor_pb2.FieldDescriptorProto.TYPE_STRING

    f = mr.field.add(); f.name = "channel_type"; f.number = 78
    f.label = descriptor_pb2.FieldDescriptorProto.LABEL_OPTIONAL
    f.type = descriptor_pb2.FieldDescriptorProto.TYPE_INT32

    f = mr.field.add(); f.name = "cpu_architecture_flag"; f.number = 79
    f.label = descriptor_pb2.FieldDescriptorProto.LABEL_OPTIONAL
    f.type = descriptor_pb2.FieldDescriptorProto.TYPE_INT32

    f = mr.field.add(); f.name = "cpu_architecture"; f.number = 81
    f.label = descriptor_pb2.FieldDescriptorProto.LABEL_OPTIONAL
    f.type = descriptor_pb2.FieldDescriptorProto.TYPE_STRING

    f = mr.field.add(); f.name = "client_version_code"; f.number = 83
    f.label = descriptor_pb2.FieldDescriptorProto.LABEL_OPTIONAL
    f.type = descriptor_pb2.FieldDescriptorProto.TYPE_STRING

    f = mr.field.add(); f.name = "graphics_api"; f.number = 86
    f.label = descriptor_pb2.FieldDescriptorProto.LABEL_OPTIONAL
    f.type = descriptor_pb2.FieldDescriptorProto.TYPE_STRING

    f = mr.field.add(); f.name = "supported_astc_bitset"; f.number = 87
    f.label = descriptor_pb2.FieldDescriptorProto.LABEL_OPTIONAL
    f.type = descriptor_pb2.FieldDescriptorProto.TYPE_INT32

    f = mr.field.add(); f.name = "login_open_id_type"; f.number = 88
    f.label = descriptor_pb2.FieldDescriptorProto.LABEL_OPTIONAL
    f.type = descriptor_pb2.FieldDescriptorProto.TYPE_INT32

    f = mr.field.add(); f.name = "loading_time"; f.number = 92
    f.label = descriptor_pb2.FieldDescriptorProto.LABEL_OPTIONAL
    f.type = descriptor_pb2.FieldDescriptorProto.TYPE_INT32

    f = mr.field.add(); f.name = "release_channel"; f.number = 93
    f.label = descriptor_pb2.FieldDescriptorProto.LABEL_OPTIONAL
    f.type = descriptor_pb2.FieldDescriptorProto.TYPE_STRING

    f = mr.field.add(); f.name = "extra_info"; f.number = 94
    f.label = descriptor_pb2.FieldDescriptorProto.LABEL_OPTIONAL
    f.type = descriptor_pb2.FieldDescriptorProto.TYPE_STRING

    f = mr.field.add(); f.name = "android_engine_init_flag"; f.number = 95
    f.label = descriptor_pb2.FieldDescriptorProto.LABEL_OPTIONAL
    f.type = descriptor_pb2.FieldDescriptorProto.TYPE_INT32

    f = mr.field.add(); f.name = "if_push"; f.number = 97
    f.label = descriptor_pb2.FieldDescriptorProto.LABEL_OPTIONAL
    f.type = descriptor_pb2.FieldDescriptorProto.TYPE_INT32

    f = mr.field.add(); f.name = "is_vpn"; f.number = 98
    f.label = descriptor_pb2.FieldDescriptorProto.LABEL_OPTIONAL
    f.type = descriptor_pb2.FieldDescriptorProto.TYPE_INT32

    f = mr.field.add(); f.name = "origin_platform_type"; f.number = 99
    f.label = descriptor_pb2.FieldDescriptorProto.LABEL_OPTIONAL
    f.type = descriptor_pb2.FieldDescriptorProto.TYPE_STRING

    f = mr.field.add(); f.name = "primary_platform_type"; f.number = 100
    f.label = descriptor_pb2.FieldDescriptorProto.LABEL_OPTIONAL
    f.type = descriptor_pb2.FieldDescriptorProto.TYPE_STRING

    resp = fdp.message_type.add()
    resp.name = "MajorLoginResponse"
    fr = resp.field.add(); fr.name = "accountId"; fr.number = 1
    fr.label = descriptor_pb2.FieldDescriptorProto.LABEL_OPTIONAL
    fr.type = descriptor_pb2.FieldDescriptorProto.TYPE_INT64

    fr = resp.field.add(); fr.name = "jwt"; fr.number = 8
    fr.label = descriptor_pb2.FieldDescriptorProto.LABEL_OPTIONAL
    fr.type = descriptor_pb2.FieldDescriptorProto.TYPE_STRING

    pool = descriptor_pool.DescriptorPool()
    pool.AddSerializedFile(fdp.SerializeToString())

    mr_desc = pool.FindMessageTypeByName("MajorLogin")
    resp_desc = pool.FindMessageTypeByName("MajorLoginResponse")

    MajorLogin = message_factory.GetMessageClass(mr_desc)
    MajorLoginResponse = message_factory.GetMessageClass(resp_desc)
    return MajorLogin, MajorLoginResponse

MajorLogin, MajorLoginResponse = build_majorlogin_proto()

def pkcs7_unpad(data: bytes) -> bytes:
    if not data:
        return data
    pad_len = data[-1]
    if pad_len < 1 or pad_len > AES.block_size:
        raise ValueError("Invalid PKCS7 padding")
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

def issue_jwt(access_token: str, open_id: str, uid: int, expires_seconds: int = 8 * 3600):
    now = int(time.time())
    payload = {
        "sub": str(uid),
        "open_id": open_id,
        "access_token": access_token,
        "iat": now,
        "exp": now + int(expires_seconds),
    }
    token = jwt.encode(payload, JWT_SECRET, algorithm="HS256")

    if isinstance(token, bytes):
        token = token.decode()
    return token

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

@app.route("/MajorLogin", methods=["POST"])
def major_login():
    ciphertext = request.get_data()
    if not ciphertext:
        return jsonify({"error": "empty body"}), 400

    try:
        plaintext = aes_cbc_decrypt(ciphertext, AES_KEY, AES_IV)
    except Exception as e:
        return jsonify({"error": "AES decrypt failed", "detail": str(e)}), 400

    try:
        req = MajorLogin()
        req.ParseFromString(plaintext)
    except Exception as e:
        return jsonify({"error": "Protobuf parse failed", "detail": str(e)}), 400

    try:
        uid = int(getattr(req, "uid", 0) or 0)
    except Exception:
        return jsonify({"error": "invalid uid field"}), 400

    access_token = getattr(req, "access_token", "") or ""
    open_id = getattr(req, "open_id", "") or ""

    if uid <= 0 or not access_token or not open_id:
        return jsonify({"error": "uid, access_token and open_id are required"}), 400

    tokens_ref = db.reference(f"guest/{uid}/tokens")
    stored = tokens_ref.get()
    if not stored:
        return jsonify({"error": "user tokens not found"}, 404)

    stored_access = stored.get("access_token")
    stored_open = stored.get("open_id")
    if stored_access is None or stored_open is None:
        return jsonify({"error": "stored tokens incomplete"}, 403)

    if access_token != stored_access or open_id != stored_open:
        return jsonify({"error": "access_token or open_id mismatch"}, 403)

    jwt_token = issue_jwt(access_token, open_id, uid, expires_seconds=8 * 3600)
    
    account_ref = db.reference(f"guest/{uid}/profile")
    stored = account_ref.get()
    accountId = stored.get("accountId")

    now_iso = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    ts = int(time.time())

    profile = {
        "accountId": accountId,
        "login_time": now_iso,
        "uid": uid,
        "open_id": open_id,
        "access_token": access_token,
        "jwt": jwt_token,
        "proto_raw_hex": binascii.hexlify(plaintext).decode(),
    }

    ACCEPTED_FIELDS = [
        "event_time",
        "game_name",
        "platform_id",
        "client_version",
        "system_software",
        "system_hardware",
        "telecom_operator",
        "network_type",
        "screen_width",
        "screen_height",
        "screen_dpi",
        "processor_details",
        "memory",
        "gpu_renderer",
        "gpu_version",
        "unique_device_id",
        "client_ip",
        "language",
        "open_id",
        "open_id_type",
        "device_type",
        "device_model",
        "platform_sdk_id",
        "network_operator_a",
        "network_type_a",
        "client_using_version",
        "external_storage_total",
        "external_storage_available",
        "internal_storage_total",
        "internal_storage_available",
        "game_disk_storage_available",
        "game_disk_storage_total",
        "external_sdcard_avail_storage",
        "external_sdcard_total_storage",
        "login_by",
        "library_path",
        "cpu_type",
        "library_token",
        "channel_type",
        "cpu_architecture",
        "client_version_code",
        "graphics_api",
        "supported_astc_bitset",
        "login_open_id_type",
        "loading_time",
        "release_channel",
        "android_engine_init_flag",
        "if_push",
        "is_vpn",
        "origin_platform_type",
        "primary_platform_type"
    ]
    
    for field in ACCEPTED_FIELDS:
        val = getattr(req, field, None)
        if val not in (None, "", 0):
            profile[field] = val

    try:
        key = f"guest/{uid}/logins/{ts}"
        db.reference(key).set(profile)
        db.reference(f"guest/{uid}/last_login").set({"time": now_iso, "jwt": jwt_token})
    except Exception as e:
        return jsonify({"error": "DB write failed", "detail": str(e)}), 500

    resp = MajorLoginResponse()
    resp.accountId = int(accountId)
    resp.jwt = jwt_token
    resp_bytes = resp.SerializeToString()
    resp_hex = binascii.hexlify(resp_bytes).decode()
    return Response(resp_hex, mimetype="text/plain")

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))