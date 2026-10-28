"""VeriGuard engine: quyết định -> xác minh ngoài băng (OOB) -> phê duyệt kép -> thực thi.

Theo mô hình Zero Trust (Tuần 6): submit() đóng vai PDP - Policy Decision Point (chấm điểm ngữ cảnh +
chính sách -> ALLOW / STEP_UP / DUAL_APPROVAL / DENY); execute() đóng vai PEP - Policy Enforcement Point
(chỉ phát lệnh chuyển tiền khi mọi điều kiện của PDP đã được đáp ứng).

Ba nguyên tắc chống giả mạo:
1. Không tin nội dung chỉ vì nó "trông thật": kênh voice/video/email/chat chỉ là lời khai.
2. Xác minh qua kênh độc lập lấy từ danh bạ tin cậy, có ký số bằng khoá trên thiết bị đã đăng ký.
3. Mọi xác minh / phê duyệt gắn với digest của giao dịch: đổi số tiền hay tài khoản là mất hiệu lực.
"""
import secrets
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from . import crypto
from .audit import AuditLog
from .models import CHANNEL_PORTAL_SIGNED, Decision, PaymentRequest
from .risk import score_request

ALLOW_MAX_SCORE = 20
STEP_UP_MAX_SCORE = 60
CHALLENGE_TTL = timedelta(minutes=5)
NEW_BENEFICIARY_HOLD = timedelta(minutes=30)

ALLOW = "ALLOW"
STEP_UP = "STEP_UP"
DUAL_APPROVAL = "DUAL_APPROVAL"
DENY = "DENY"
MAX_CHALLENGES_PER_REQUEST = 3   # chống MFA fatigue / push spam (Bài 5, Tuần 6)


class VerificationError(Exception):
    """Một bước xác minh thất bại; lý do được ghi vào nhật ký kiểm toán."""


@dataclass
class Challenge:
    nonce: str
    request_digest: str
    target_employee: str
    sent_to: str
    expires_at: datetime
    used: bool = False


@dataclass
class RequestState:
    request: PaymentRequest
    digest_at_submit: str
    decision: Decision
    hold_until: datetime | None = None
    oob_verified: bool = False
    approvals: set = field(default_factory=set)
    status: str = "PENDING"
    challenges_issued: int = 0


class VeriGuard:
    def __init__(self, directory, audit: AuditLog):
        self.directory = directory
        self.audit = audit
        self._states = {}
        self._challenges = {}

    # ---------- 1. Tiếp nhận & quyết định ----------
    def submit(self, request: PaymentRequest) -> Decision:
        score, reasons, signals = score_request(request, self.directory)
        requester = self.directory.get(request.claimed_requester)

        if requester is None:
            decision = Decision(request.request_id, DENY, score, reasons, [])
        elif request.channel == CHANNEL_PORTAL_SIGNED and not crypto.verify(
                requester.public_key, request.signature, "request", request.digest()):
            reasons.append("chữ ký thiết bị không hợp lệ - nội dung bị sửa hoặc không phải từ thiết bị đã đăng ký")
            decision = Decision(request.request_id, DENY, score, reasons, [])
        elif score <= ALLOW_MAX_SCORE and request.channel == CHANNEL_PORTAL_SIGNED:
            decision = Decision(request.request_id, ALLOW, score, reasons, [])
        elif score <= STEP_UP_MAX_SCORE:
            decision = Decision(request.request_id, STEP_UP, score, reasons, ["oob_verification"])
        else:
            decision = Decision(request.request_id, DUAL_APPROVAL, score, reasons,
                                ["oob_verification", "independent_approval"])

        state = RequestState(request, request.digest(), decision)
        if decision.action == DUAL_APPROVAL and "new_beneficiary" in signals:
            state.hold_until = request.received_at + NEW_BENEFICIARY_HOLD
            decision.required_steps.append("cooling_off_hold")
        if decision.action == DENY:
            state.status = "REJECTED"
        self._states[request.request_id] = state
        self.audit.append("submitted", request=request.to_log(), digest=state.digest_at_submit,
                          action=decision.action, score=score, reasons=reasons)
        return decision

    # ---------- 2. Xác minh ngoài băng ----------
    def issue_challenge(self, request_id, now) -> Challenge:
        state = self._require_state(request_id)
        requester = self.directory.get(state.request.claimed_requester)
        if state.status == "REJECTED":
            raise VerificationError("giao dịch đã bị từ chối")
        if state.challenges_issued >= MAX_CHALLENGES_PER_REQUEST:
            self.audit.append("challenge_limit_reached", request_id=request_id, alert="possible_mfa_fatigue")
            raise VerificationError("vượt số lần gửi xác minh cho phép (chống MFA fatigue)")
        state.challenges_issued += 1
        # Gửi tới số/thiết bị trong danh bạ, KHÔNG dùng callback_hint do người gửi cung cấp.
        challenge = Challenge(
            nonce=secrets.token_hex(16),
            request_digest=state.digest_at_submit,
            target_employee=requester.employee_id,
            sent_to=requester.registered_phone,
            expires_at=now + CHALLENGE_TTL,
        )
        self._challenges[challenge.nonce] = challenge
        self.audit.append("challenge_issued", request_id=request_id, sent_to=challenge.sent_to,
                          ignored_callback_hint=state.request.callback_hint or None)
        return challenge

    def submit_challenge_response(self, request_id, nonce, response_signature, now):
        state = self._require_state(request_id)
        try:
            challenge = self._challenges.get(nonce)
            if challenge is None:
                raise VerificationError("nonce không tồn tại")
            if challenge.used:
                raise VerificationError("nonce đã dùng (replay)")
            if now > challenge.expires_at:
                raise VerificationError("thử thách đã hết hạn")
            if challenge.request_digest != state.request.digest():
                raise VerificationError("thử thách thuộc giao dịch khác hoặc giao dịch đã bị sửa")
            requester = self.directory.get(challenge.target_employee)
            if not crypto.verify(requester.public_key, response_signature, "confirm", nonce, challenge.request_digest):
                raise VerificationError("chữ ký phản hồi không hợp lệ (không phải thiết bị đã đăng ký)")
        except VerificationError as error:
            self.audit.append("challenge_failed", request_id=request_id, reason=str(error))
            raise
        finally:
            if nonce in self._challenges:
                self._challenges[nonce].used = True   # dùng một lần, kể cả khi thất bại
        state.oob_verified = True
        self.audit.append("challenge_passed", request_id=request_id)

    def report_declined(self, request_id, employee_id):
        """Người thật bấm 'Không phải tôi' trên thiết bị -> chặn và báo động."""
        state = self._require_state(request_id)
        state.status = "REJECTED"
        self.audit.append("declined_by_owner", request_id=request_id, employee=employee_id, alert="possible_impersonation")

    # ---------- 3. Phê duyệt độc lập ----------
    def approve(self, request_id, approver_id, approval_signature):
        state = self._require_state(request_id)
        approver = self.directory.get(approver_id)
        try:
            if approver is None or not approver.can_approve:
                raise VerificationError(f"{approver_id} không có quyền phê duyệt")
            if approver_id == state.request.claimed_requester:
                raise VerificationError("người yêu cầu không được tự phê duyệt")
            if not crypto.verify(approver.public_key, approval_signature, "approve", state.request.digest()):
                raise VerificationError("chữ ký phê duyệt không khớp giao dịch hiện tại")
        except VerificationError as error:
            self.audit.append("approval_failed", request_id=request_id, approver=approver_id, reason=str(error))
            raise
        state.approvals.add(approver_id)
        self.audit.append("approved", request_id=request_id, approver=approver_id)

    # ---------- 4. Thực thi ----------
    def execute(self, request_id, now):
        state = self._require_state(request_id)
        try:
            if state.status == "REJECTED":
                raise VerificationError("giao dịch đã bị từ chối")
            if state.request.digest() != state.digest_at_submit:
                raise VerificationError("nội dung giao dịch đã bị sửa sau khi tiếp nhận")
            steps = state.decision.required_steps
            if "oob_verification" in steps and not state.oob_verified:
                raise VerificationError("chưa xác minh ngoài băng")
            if "independent_approval" in steps and not state.approvals:
                raise VerificationError("chưa có phê duyệt độc lập")
            if state.hold_until and now < state.hold_until:
                raise VerificationError(f"đang trong thời gian chờ an toàn tới {state.hold_until:%H:%M}")
        except VerificationError as error:
            state.status = "BLOCKED" if state.status != "REJECTED" else state.status
            self.audit.append("execute_blocked", request_id=request_id, reason=str(error))
            raise
        state.status = "EXECUTED"
        self.audit.append("executed", request_id=request_id, amount=state.request.amount,
                          beneficiary=state.request.beneficiary_account)
        return state.status

    def status(self, request_id):
        return self._require_state(request_id).status

    def _require_state(self, request_id):
        if request_id not in self._states:
            raise KeyError(f"không có yêu cầu {request_id}")
        return self._states[request_id]


class RegisteredDevice:
    """Mô phỏng app trên điện thoại đã đăng ký: hiển thị chi tiết giao dịch và ký khi chủ máy đồng ý."""

    def __init__(self, employee_id, secret_key: bytes):
        self.employee_id = employee_id
        self._secret_key = secret_key   # mô phỏng khoá trong Secure Element/TPM, không xuất ra ngoài

    def sign_request(self, request: PaymentRequest):
        return crypto.sign(self._secret_key, "request", request.digest())

    def confirm(self, challenge: Challenge):
        return crypto.sign(self._secret_key, "confirm", challenge.nonce, challenge.request_digest)

    def approve(self, request: PaymentRequest):
        return crypto.sign(self._secret_key, "approve", request.digest())
