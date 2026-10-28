# VeriGuard – Prototype

Hệ thống xác minh yêu cầu chuyển tiền chống giả mạo (deepfake video/giọng nói, email giả, tài khoản bị chiếm) cho doanh nghiệp nhỏ. Chỉ dùng thư viện chuẩn Python 3.10+.

```
python demo.py              # 4 kịch bản demo
python -m unittest -v       # 22 test case (TC01–TC22)
```

| Module | Vai trò |
|---|---|
| `veriguard/models.py` | Yêu cầu chuyển tiền, digest SHA-256 của các trường quyết định giao dịch |
| `veriguard/directory.py` | Danh bạ tin cậy: nhân viên, số đăng ký, khoá công khai thiết bị, người thụ hưởng đã xác minh |
| `veriguard/risk.py` | Chấm điểm ngữ cảnh (kênh, người thụ hưởng, hạn mức, giờ, ngôn ngữ thúc ép, tên miền giả, DMARC, deepfake score) |
| `veriguard/engine.py` | PDP (quyết định ALLOW / STEP_UP / DUAL_APPROVAL / DENY), xác minh ngoài băng, phê duyệt kép, PEP (thực thi) |
| `veriguard/crypto.py` | Chữ ký số Ed25519 (mã tham chiếu RFC 8032) |
| `veriguard/audit.py` | Nhật ký kiểm toán chuỗi HMAC-SHA256 |
| `veriguard/sample_data.py` | Dữ liệu giả lập Công ty An Phát |

Lưu ý: `crypto.py` là bản minh hoạ để không phụ thuộc thư viện ngoài; triển khai thật dùng thư viện đã kiểm định (libsodium/`cryptography`, WebAuthn/passkey) và khoá trong Secure Element/HSM. Toàn bộ dữ liệu là giả lập.
