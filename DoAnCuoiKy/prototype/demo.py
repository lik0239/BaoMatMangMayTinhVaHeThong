"""Demo VeriGuard cho buổi thuyết trình: 4 kịch bản, in từng bước quyết định.

Chạy: python demo.py
"""
import sys
from datetime import timedelta

from veriguard.engine import VeriGuard, VerificationError
from veriguard.models import PaymentRequest
from veriguard.sample_data import WORK_TIME, attacker_device, build_environment, new_audit_log

NEW_ACCOUNT = "9704229988776655"


def banner(title):
    print("\n" + "=" * 78 + f"\n {title}\n" + "=" * 78)


def show_decision(decision):
    print(f"  PDP quyết định: {decision.action}  (điểm rủi ro {decision.risk_score})")
    for reason in decision.reasons:
        print(f"     {reason}")
    if decision.required_steps:
        print(f"  Bước bắt buộc: {', '.join(decision.required_steps)}")


def attempt(label, action):
    try:
        result = action()
        print(f"  [OK]   {label}" + (f" -> {result}" if result else ""))
    except VerificationError as error:
        print(f"  [CHẶN] {label}: {error}")


def scenario_normal(guard, devices):
    banner("KỊCH BẢN 1 - Kế toán gửi đề nghị thanh toán hoá đơn qua email (bình thường)")
    request = PaymentRequest("INV-1031", "E03", "email", 20_000_000, "0011001234567",
                             "CONG TY TNHH VAN PHONG PHAM SAO MAI", "Thanh toán hoá đơn VPP tháng 10",
                             WORK_TIME, sender_address="nam.pham@anphat.vn", metadata={"dmarc": "pass"})
    show_decision(guard.submit(request))
    challenge = guard.issue_challenge(request.request_id, WORK_TIME)
    print(f"  Gửi thử thách tới thiết bị đã đăng ký ({challenge.sent_to}), hạn {challenge.expires_at:%H:%M}")
    attempt("Anh Nam xác nhận trên app", lambda: guard.submit_challenge_response(
        request.request_id, challenge.nonce, devices["E03"].confirm(challenge), WORK_TIME))
    attempt("PEP thực thi lệnh chuyển tiền", lambda: guard.execute(request.request_id, WORK_TIME))


def scenario_deepfake(guard, devices):
    banner("KỊCH BẢN 2 - Video call deepfake 'Giám đốc' yêu cầu chuyển gấp 450 triệu")
    request = PaymentRequest("CEO-0715", "E01", "video_call", 450_000_000, NEW_ACCOUNT, "NGUYEN VAN K",
                             "Anh đang họp với đối tác, chuyển gấp khoản đặt cọc, giữ bí mật giúp anh, đừng gọi lại",
                             WORK_TIME, sender_address="Tran Minh (Zalo)", callback_hint="0987654321",
                             deepfake_score=0.08)
    print("  Bộ phát hiện deepfake báo 0.08 (trông thật) -> chỉ là tín hiệu phụ, không phải căn cứ để tin")
    show_decision(guard.submit(request))
    challenge = guard.issue_challenge(request.request_id, WORK_TIME)
    print(f"  Thử thách gửi tới số trong danh bạ {challenge.sent_to}, KHÔNG gọi số {request.callback_hint} kẻ gian đưa")
    attempt("Kẻ gian ký bằng thiết bị của mình", lambda: guard.submit_challenge_response(
        request.request_id, challenge.nonce, attacker_device("E01").confirm(challenge), WORK_TIME))
    print("  Giám đốc thật nhận thông báo trên điện thoại, bấm 'Không phải tôi'")
    guard.report_declined(request.request_id, "E01")
    attempt("PEP thực thi lệnh chuyển tiền", lambda: guard.execute(request.request_id, WORK_TIME + timedelta(hours=1)))


def scenario_tamper(guard, devices):
    banner("KỊCH BẢN 3 - Đã xác minh xong, kẻ gian chen vào: 'Anh đổi số tài khoản nhận nhé'")
    request = PaymentRequest("INV-1032", "E03", "email", 25_000_000, "0451000765432",
                             "CONG TY CP LOGISTICS BAC NAM", "Phí vận chuyển tháng 10", WORK_TIME,
                             sender_address="nam.pham@anphat.vn", metadata={"dmarc": "pass"})
    show_decision(guard.submit(request))
    challenge = guard.issue_challenge(request.request_id, WORK_TIME)
    attempt("Xác nhận trên app", lambda: guard.submit_challenge_response(
        request.request_id, challenge.nonce, devices["E03"].confirm(challenge), WORK_TIME))
    request.beneficiary_account = NEW_ACCOUNT
    print(f"  Tài khoản nhận bị đổi thành {NEW_ACCOUNT} -> digest giao dịch thay đổi")
    attempt("PEP thực thi lệnh chuyển tiền", lambda: guard.execute(request.request_id, WORK_TIME))


def scenario_real_ceo(guard, devices):
    banner("KỊCH BẢN 4 - Giám đốc THẬT đặt cọc 300 triệu cho nhà cung cấp mới (rủi ro cao nhưng hợp lệ)")
    request = PaymentRequest("CEO-0716", "E01", "video_call", 300_000_000, NEW_ACCOUNT,
                             "CONG TY TNHH THIET BI MOI", "Đặt cọc hợp đồng thiết bị", WORK_TIME)
    show_decision(guard.submit(request))
    challenge = guard.issue_challenge(request.request_id, WORK_TIME)
    attempt("Giám đốc xác nhận trên app", lambda: guard.submit_challenge_response(
        request.request_id, challenge.nonce, devices["E01"].confirm(challenge), WORK_TIME))
    attempt("Giám đốc tự phê duyệt", lambda: guard.approve(request.request_id, "E01", devices["E01"].approve(request)))
    attempt("Kế toán trưởng phê duyệt độc lập", lambda: guard.approve(request.request_id, "E02", devices["E02"].approve(request)))
    attempt("Thực thi sau 10 phút", lambda: guard.execute(request.request_id, WORK_TIME + timedelta(minutes=10)))
    attempt("Thực thi sau 31 phút", lambda: guard.execute(request.request_id, WORK_TIME + timedelta(minutes=31)))


def main():
    sys.stdout.reconfigure(encoding="utf-8")
    directory, devices = build_environment()
    guard = VeriGuard(directory, new_audit_log())
    for scenario in (scenario_normal, scenario_deepfake, scenario_tamper, scenario_real_ceo):
        scenario(guard, devices)

    banner("NHẬT KÝ KIỂM TOÁN (chuỗi HMAC)")
    for entry in guard.audit.entries:
        print(f"  #{entry['seq']:02d} {entry['event']:<22} {entry['data'].get('request_id', entry['data'].get('request', {}).get('request_id', ''))}"
              f"  hash={entry['hash'][:12]}…")
    print(f"  Kiểm tra toàn vẹn chuỗi: {guard.audit.verify_chain()}")


if __name__ == "__main__":
    main()
