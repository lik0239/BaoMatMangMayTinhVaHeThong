"""Mô hình dữ liệu của VeriGuard."""
import hashlib
import json
from dataclasses import dataclass, field, asdict
from datetime import datetime

# Kênh mà yêu cầu đi vào hệ thống. Chỉ PORTAL_SIGNED chứng minh được danh tính (có chữ ký thiết bị);
# các kênh còn lại chỉ là "lời khai" - nội dung có thể bị giả mạo (deepfake, tài khoản bị chiếm, email giả).
CHANNEL_PORTAL_SIGNED = "portal_signed"
CHANNEL_EMAIL = "email"
CHANNEL_CHAT = "chat"
CHANNEL_VOICE_CALL = "voice_call"
CHANNEL_VIDEO_CALL = "video_call"
UNVERIFIED_CHANNELS = {CHANNEL_EMAIL, CHANNEL_CHAT, CHANNEL_VOICE_CALL, CHANNEL_VIDEO_CALL}


@dataclass
class Employee:
    employee_id: str
    name: str
    role: str                 # "ceo", "cfo", "accountant", "staff"
    registered_phone: str     # số do phòng nhân sự xác minh khi onboard, KHÔNG lấy từ yêu cầu
    public_key: bytes         # khoá công khai Ed25519 của thiết bị đã đăng ký; khoá bí mật không rời thiết bị
    approval_limit: int       # hạn mức một người được tự yêu cầu (VND)
    can_approve: bool = False


@dataclass
class PaymentRequest:
    request_id: str
    claimed_requester: str            # employee_id mà người gửi TỰ XƯNG
    channel: str
    amount: int
    beneficiary_account: str
    beneficiary_name: str
    message: str
    received_at: datetime
    sender_address: str = ""          # email / số điện thoại hiển thị - có thể giả mạo
    callback_hint: str = ""           # số "gọi lại cho tôi" do người gửi đưa - KHÔNG BAO GIỜ dùng
    deepfake_score: float | None = None  # điểm từ bộ phát hiện deepfake bên ngoài (0 = trông thật)
    signature: str = ""               # chữ ký Ed25519 từ thiết bị đã đăng ký (chỉ có ở kênh portal)
    metadata: dict = field(default_factory=dict)

    def signed_fields(self):
        """Các trường quyết định ý nghĩa giao dịch; mọi chữ ký / phê duyệt đều gắn với chúng."""
        return {
            "request_id": self.request_id,
            "claimed_requester": self.claimed_requester,
            "amount": self.amount,
            "beneficiary_account": self.beneficiary_account,
            "beneficiary_name": self.beneficiary_name,
        }

    def digest(self):
        canonical = json.dumps(self.signed_fields(), sort_keys=True, ensure_ascii=False)
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    def to_log(self):
        data = asdict(self)
        data["received_at"] = self.received_at.isoformat()
        data.pop("signature", None)
        return data


@dataclass
class Decision:
    request_id: str
    action: str                 # ALLOW / STEP_UP / DUAL_APPROVAL / REJECT
    risk_score: int
    reasons: list
    required_steps: list
