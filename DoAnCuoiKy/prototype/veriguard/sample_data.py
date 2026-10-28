"""Dữ liệu mẫu (giả lập) cho demo và test: Công ty TNHH An Phát, tên miền anphat.vn."""
import hashlib
from datetime import datetime

from . import crypto
from .audit import AuditLog
from .directory import TrustedDirectory
from .engine import RegisteredDevice
from .models import Employee

COMPANY_DOMAIN = "anphat.vn"
WORK_TIME = datetime(2026, 11, 3, 10, 15)      # thứ Ba, 10:15
NIGHT_TIME = datetime(2026, 11, 7, 21, 40)     # thứ Bảy, 21:40

STAFF = [
    # employee_id, tên, vai trò, số đăng ký, hạn mức tự yêu cầu, quyền phê duyệt
    ("E01", "Trần Minh (Giám đốc)", "ceo", "0901000001", 500_000_000, True),
    ("E02", "Lê Hoa (Kế toán trưởng)", "cfo", "0901000002", 200_000_000, True),
    ("E03", "Phạm Nam (Kế toán)", "accountant", "0901000003", 30_000_000, False),
    ("E04", "Võ Lan (Nhân viên)", "staff", "0901000004", 5_000_000, False),
]


def demo_secret(label):
    """Khoá bí mật cố định cho demo (tái lập được). Thực tế: sinh ngẫu nhiên trong Secure Element."""
    return hashlib.sha256(f"veriguard-demo-{label}".encode()).digest()


def build_environment():
    """Trả về (directory, devices): directory chỉ chứa khoá công khai; devices giữ khoá bí mật."""
    directory = TrustedDirectory(COMPANY_DOMAIN)
    devices = {}
    for employee_id, name, role, phone, limit, can_approve in STAFF:
        secret = demo_secret(employee_id)
        directory.add_employee(Employee(employee_id, name, role, phone, crypto.public_key(secret), limit, can_approve))
        devices[employee_id] = RegisteredDevice(employee_id, secret)
    directory.add_beneficiary("0011001234567", "CONG TY TNHH VAN PHONG PHAM SAO MAI")
    directory.add_beneficiary("0451000765432", "CONG TY CP LOGISTICS BAC NAM")
    return directory, devices


def attacker_device(target_employee_id):
    """Thiết bị của kẻ tấn công tự xưng là nhân viên: có khoá riêng, KHÔNG phải khoá đã đăng ký."""
    return RegisteredDevice(target_employee_id, demo_secret(f"attacker-{target_employee_id}"))


def new_audit_log():
    """Khoá kiểm toán: thực tế lấy từ Secret Manager/KMS, không hard-code, không ghi vào log."""
    return AuditLog(demo_secret("audit-key"))
