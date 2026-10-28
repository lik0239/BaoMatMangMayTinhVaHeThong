"""Chấm điểm rủi ro: mỗi tín hiệu cộng điểm và để lại lý do có thể giải thích được."""
import unicodedata

from .models import UNVERIFIED_CHANNELS, CHANNEL_PORTAL_SIGNED

LARGE_AMOUNT = 50_000_000          # VND
BUSINESS_HOURS = range(8, 18)
URGENCY_KEYWORDS = [
    "gap", "khan", "ngay lap tuc", "bi mat", "dung goi lai", "dung bao ai",
    "trong hom nay", "urgent", "confidential", "khong goi duoc",
]
DEEPFAKE_SUSPECT_THRESHOLD = 0.5

WEIGHTS = {
    "unverified_channel": 30,
    "new_beneficiary": 25,
    "beneficiary_name_mismatch": 40,
    "over_requester_limit": 20,
    "large_amount": 15,
    "urgency_pressure": 15,
    "outside_business_hours": 10,
    "lookalike_sender": 35,
    "callback_number_supplied": 10,
    "deepfake_suspected": 20,
    "unknown_requester": 50,
    "email_auth_failed": 30,
}


def strip_accents(text):
    normalized = unicodedata.normalize("NFD", text.lower()).replace("đ", "d")
    return "".join(ch for ch in normalized if unicodedata.category(ch) != "Mn")


def edit_distance(a, b):
    previous = list(range(len(b) + 1))
    for i, ch_a in enumerate(a, 1):
        current = [i]
        for j, ch_b in enumerate(b, 1):
            current.append(min(previous[j] + 1, current[j - 1] + 1, previous[j - 1] + (ch_a != ch_b)))
        previous = current
    return previous[-1]


MULTI_LABEL_SUFFIXES = {"com.vn", "net.vn", "org.vn", "edu.vn", "gov.vn", "co.uk"}


def registrable_domain(hostname):
    """Đọc tên miền từ phải sang trái (TH2): 'anphat.vn.secure-pay.com' -> 'secure-pay.com'."""
    labels = hostname.lower().strip(".").split(".")
    suffix_size = 2 if ".".join(labels[-2:]) in MULTI_LABEL_SUFFIXES else 1
    return ".".join(labels[-(suffix_size + 1):])


def is_lookalike_domain(sender_address, company_domain):
    """Tên miền đăng ký khác tên miền công ty nhưng cố tạo cảm giác chính chủ.

    Bắt cả hai kiểu: gõ sai gần giống (anphat.vn -> anphatt.vn, an-phat.vn) và chèn tên công ty
    vào subdomain (anphat.vn.secure-pay.com) như URL microflice365.com trong TH2.
    """
    if "@" not in sender_address:
        return False
    hostname = sender_address.rsplit("@", 1)[1].lower()
    sender_domain = registrable_domain(hostname)
    if sender_domain == company_domain:
        return False
    brand = company_domain.split(".")[0]
    return edit_distance(sender_domain, company_domain) <= 2 or brand in hostname.replace("-", "")


def score_request(request, directory):
    reasons = []
    signals = set()

    def hit(signal, reason):
        signals.add(signal)
        reasons.append(f"+{WEIGHTS[signal]} {reason}")

    requester = directory.get(request.claimed_requester)
    if requester is None:
        hit("unknown_requester", "người yêu cầu không có trong danh bạ tin cậy")

    if request.channel in UNVERIFIED_CHANNELS:
        hit("unverified_channel", f"kênh {request.channel} không chứng minh được danh tính (có thể deepfake / bị chiếm tài khoản)")

    if not directory.is_known_beneficiary(request.beneficiary_account):
        hit("new_beneficiary", f"tài khoản thụ hưởng {request.beneficiary_account} chưa từng được xác minh")
    elif directory.beneficiary_name(request.beneficiary_account) != request.beneficiary_name:
        hit("beneficiary_name_mismatch", "tên người thụ hưởng không khớp tên đã xác minh của tài khoản")

    if requester and request.amount > requester.approval_limit:
        hit("over_requester_limit", f"số tiền vượt hạn mức {requester.approval_limit:,} của người yêu cầu")
    if request.amount >= LARGE_AMOUNT:
        hit("large_amount", f"số tiền lớn (>= {LARGE_AMOUNT:,})")

    plain_message = strip_accents(request.message)
    pressure = [kw for kw in URGENCY_KEYWORDS if kw in plain_message]
    if pressure:
        hit("urgency_pressure", f"ngôn ngữ thúc ép / giữ bí mật: {', '.join(pressure)}")

    if request.received_at.hour not in BUSINESS_HOURS or request.received_at.weekday() >= 5:
        hit("outside_business_hours", "ngoài giờ làm việc")

    if is_lookalike_domain(request.sender_address, directory.company_domain):
        hit("lookalike_sender", f"địa chỉ gửi {request.sender_address} giả dạng tên miền công ty")

    # SPF/DKIM/DMARC (Tuần 7): fail là dấu hiệu giả mạo; pass KHÔNG cộng tin cậy vì hộp thư thật vẫn có thể bị chiếm.
    email_auth = request.metadata.get("dmarc")
    if request.channel == "email" and email_auth and email_auth != "pass":
        hit("email_auth_failed", f"email không qua kiểm tra SPF/DKIM/DMARC (dmarc={email_auth})")

    if request.callback_hint:
        hit("callback_number_supplied", "người gửi tự cung cấp số gọi lại (bị bỏ qua khi xác minh)")

    if request.deepfake_score is not None and request.deepfake_score >= DEEPFAKE_SUSPECT_THRESHOLD:
        hit("deepfake_suspected", f"bộ phát hiện deepfake báo nghi vấn (score={request.deepfake_score:.2f})")

    score = sum(WEIGHTS[s] for s in signals)
    if request.channel == CHANNEL_PORTAL_SIGNED and not signals:
        reasons.append("+0 yêu cầu ký số từ thiết bị đã đăng ký, không có tín hiệu bất thường")
    return score, reasons, signals
