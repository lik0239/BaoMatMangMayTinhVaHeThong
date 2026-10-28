"""Chữ ký số Ed25519 (theo mã tham chiếu RFC 8032 §6) - chỉ dùng thư viện chuẩn.

Khoá bí mật nằm trên thiết bị đã đăng ký (mô phỏng Secure Element/TPM); máy chủ VeriGuard chỉ lưu
khoá công khai. Nếu máy chủ bị chiếm, kẻ tấn công vẫn không thể tự ký xác nhận / phê duyệt.

Lưu ý: bản cài đặt minh hoạ, không chạy thời gian hằng số; triển khai thật dùng thư viện đã kiểm định
(libsodium, cryptography) và khoá trong HSM/Secure Element.
"""
import hashlib

_p = 2**255 - 19
_q = 2**252 + 27742317777372353535851937790883648493


def _inv(x):
    return pow(x, _p - 2, _p)


_d = -121665 * _inv(121666) % _p
_sqrt_m1 = pow(2, (_p - 1) // 4, _p)


def _sha512_modq(data):
    return int.from_bytes(hashlib.sha512(data).digest(), "little") % _q


def _add(P, Q):
    A = (P[1] - P[0]) * (Q[1] - Q[0]) % _p
    B = (P[1] + P[0]) * (Q[1] + Q[0]) % _p
    C = 2 * P[3] * Q[3] * _d % _p
    D = 2 * P[2] * Q[2] % _p
    E, F, G, H = B - A, D - C, D + C, B + A
    return (E * F, G * H, F * G, E * H)


def _mul(s, P):
    Q = (0, 1, 1, 0)
    while s > 0:
        if s & 1:
            Q = _add(Q, P)
        P = _add(P, P)
        s >>= 1
    return Q


def _equal(P, Q):
    return (P[0] * Q[2] - Q[0] * P[2]) % _p == 0 and (P[1] * Q[2] - Q[1] * P[2]) % _p == 0


def _recover_x(y, sign):
    if y >= _p:
        return None
    x2 = (y * y - 1) * _inv(_d * y * y + 1)
    if x2 == 0:
        return None if sign else 0
    x = pow(x2, (_p + 3) // 8, _p)
    if (x * x - x2) % _p != 0:
        x = x * _sqrt_m1 % _p
    if (x * x - x2) % _p != 0:
        return None
    if (x & 1) != sign:
        x = _p - x
    return x


_gy = 4 * _inv(5) % _p
_gx = _recover_x(_gy, 0)
_G = (_gx, _gy, 1, _gx * _gy % _p)


def _compress(P):
    zinv = _inv(P[2])
    x, y = P[0] * zinv % _p, P[1] * zinv % _p
    return int.to_bytes(y | ((x & 1) << 255), 32, "little")


def _decompress(data):
    if len(data) != 32:
        return None
    y = int.from_bytes(data, "little")
    sign = y >> 255
    y &= (1 << 255) - 1
    x = _recover_x(y, sign)
    return None if x is None else (x, y, 1, x * y % _p)


def _expand(secret):
    if len(secret) != 32:
        raise ValueError("khoá bí mật Ed25519 phải dài 32 byte")
    h = hashlib.sha512(secret).digest()
    a = int.from_bytes(h[:32], "little")
    a &= (1 << 254) - 8
    a |= 1 << 254
    return a, h[32:]


def public_key(secret: bytes) -> bytes:
    a, _ = _expand(secret)
    return _compress(_mul(a, _G))


def _message(*parts: str) -> bytes:
    return "|".join(parts).encode("utf-8")


def sign(secret: bytes, *parts: str) -> str:
    message = _message(*parts)
    a, prefix = _expand(secret)
    A = _compress(_mul(a, _G))
    r = _sha512_modq(prefix + message)
    R = _compress(_mul(r, _G))
    s = (r + _sha512_modq(R + A + message) * a) % _q
    return (R + int.to_bytes(s, 32, "little")).hex()


def verify(public: bytes, signature_hex: str, *parts: str) -> bool:
    try:
        signature = bytes.fromhex(signature_hex or "")
    except ValueError:
        return False
    if len(signature) != 64:
        return False
    A = _decompress(public)
    R = _decompress(signature[:32])
    if A is None or R is None:
        return False
    s = int.from_bytes(signature[32:], "little")
    if s >= _q:
        return False
    h = _sha512_modq(signature[:32] + public + _message(*parts))
    return _equal(_mul(s, _G), _add(R, _mul(h, A)))
