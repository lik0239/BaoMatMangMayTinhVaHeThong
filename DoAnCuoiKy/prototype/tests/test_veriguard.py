"""Bộ test case VeriGuard: tình huống bình thường (TC01-TC03) và tình huống rủi ro (TC04-TC22).

Chạy: python -m unittest -v   (trong thư mục prototype)
"""
import hashlib
import json
import unittest
from datetime import timedelta

from veriguard import crypto
from veriguard.engine import ALLOW, DENY, DUAL_APPROVAL, STEP_UP, VeriGuard, VerificationError
from veriguard.models import PaymentRequest
from veriguard.risk import is_lookalike_domain, registrable_domain
from veriguard.sample_data import NIGHT_TIME, WORK_TIME, attacker_device, build_environment, new_audit_log

KNOWN_ACCOUNT = "0011001234567"
KNOWN_NAME = "CONG TY TNHH VAN PHONG PHAM SAO MAI"
NEW_ACCOUNT = "9704229988776655"


def make_request(request_id, requester, channel, amount, account=KNOWN_ACCOUNT, name=KNOWN_NAME,
                 message="Thanh toán hoá đơn tháng 10", at=WORK_TIME, **extra):
    return PaymentRequest(request_id, requester, channel, amount, account, name, message, at, **extra)


class VeriGuardTestCase(unittest.TestCase):
    def setUp(self):
        self.directory, self.devices = build_environment()
        self.guard = VeriGuard(self.directory, new_audit_log())

    def deepfake_ceo_request(self, request_id="R-ATK"):
        """Video call 'giám đốc' (deepfake trông rất thật) yêu cầu chuyển gấp cho tài khoản mới."""
        return make_request(request_id, "E01", "video_call", 450_000_000, NEW_ACCOUNT, "NGUYEN VAN K",
                            "Anh đang họp với đối tác, chuyển gấp khoản đặt cọc, giữ bí mật giúp anh, đừng gọi lại",
                            sender_address="Tran Minh (Zalo)", callback_hint="0987654321", deepfake_score=0.08)

    def pass_oob(self, request, device_id=None):
        challenge = self.guard.issue_challenge(request.request_id, WORK_TIME)
        device = self.devices[device_id or request.claimed_requester]
        self.guard.submit_challenge_response(request.request_id, challenge.nonce, device.confirm(challenge), WORK_TIME)
        return challenge

    # ===================== TÌNH HUỐNG BÌNH THƯỜNG =====================
    def test_tc01_signed_portal_request_known_beneficiary_is_allowed(self):
        request = make_request("R01", "E03", "portal_signed", 12_000_000)
        request.signature = self.devices["E03"].sign_request(request)
        decision = self.guard.submit(request)
        self.assertEqual(decision.action, ALLOW)
        self.assertEqual(self.guard.execute("R01", WORK_TIME), "EXECUTED")

    def test_tc02_email_request_requires_step_up_then_succeeds(self):
        request = make_request("R02", "E03", "email", 20_000_000, sender_address="nam.pham@anphat.vn",
                               metadata={"dmarc": "pass"})
        decision = self.guard.submit(request)
        self.assertEqual(decision.action, STEP_UP)
        with self.assertRaises(VerificationError):
            self.guard.execute("R02", WORK_TIME)          # chưa xác minh thì PEP không cho chạy
        self.pass_oob(request)
        self.assertEqual(self.guard.execute("R02", WORK_TIME), "EXECUTED")

    def test_tc03_real_ceo_high_risk_needs_oob_dual_approval_and_hold(self):
        request = make_request("R03", "E01", "video_call", 300_000_000, NEW_ACCOUNT, "CONG TY TNHH THIET BI MOI")
        decision = self.guard.submit(request)
        self.assertEqual(decision.action, DUAL_APPROVAL)
        self.assertIn("cooling_off_hold", decision.required_steps)
        self.pass_oob(request)
        self.guard.approve("R03", "E02", self.devices["E02"].approve(request))
        with self.assertRaises(VerificationError):
            self.guard.execute("R03", WORK_TIME + timedelta(minutes=10))    # còn trong thời gian chờ
        self.assertEqual(self.guard.execute("R03", WORK_TIME + timedelta(minutes=31)), "EXECUTED")

    # ===================== GIẢ MẠO ĐẦU VÀO (DEEPFAKE / KÊNH GIẢ) =====================
    def test_tc04_deepfake_that_looks_real_is_not_trusted(self):
        decision = self.guard.submit(self.deepfake_ceo_request())
        self.assertEqual(decision.action, DUAL_APPROVAL)    # deepfake_score thấp KHÔNG làm giảm rủi ro
        self.assertNotIn("deepfake_suspected", " ".join(decision.reasons))
        self.assertTrue(any("ngôn ngữ thúc ép" in r for r in decision.reasons))

    def test_tc05_attacker_cannot_answer_challenge_with_own_device(self):
        request = self.deepfake_ceo_request()
        self.guard.submit(request)
        challenge = self.guard.issue_challenge(request.request_id, WORK_TIME)
        forged = attacker_device("E01").confirm(challenge)
        with self.assertRaisesRegex(VerificationError, "chữ ký phản hồi không hợp lệ"):
            self.guard.submit_challenge_response(request.request_id, challenge.nonce, forged, WORK_TIME)
        with self.assertRaises(VerificationError):
            self.guard.execute(request.request_id, WORK_TIME + timedelta(hours=1))

    def test_tc06_real_owner_declines_on_registered_device(self):
        request = self.deepfake_ceo_request()
        self.guard.submit(request)
        self.guard.issue_challenge(request.request_id, WORK_TIME)
        self.guard.report_declined(request.request_id, "E01")
        with self.assertRaisesRegex(VerificationError, "đã bị từ chối"):
            self.guard.execute(request.request_id, WORK_TIME + timedelta(hours=1))
        self.assertIn("declined_by_owner", self.guard.audit.events())

    def test_tc07_callback_number_from_request_is_ignored(self):
        request = self.deepfake_ceo_request()
        self.guard.submit(request)
        challenge = self.guard.issue_challenge(request.request_id, WORK_TIME)
        self.assertEqual(challenge.sent_to, self.directory.get("E01").registered_phone)
        self.assertNotEqual(challenge.sent_to, request.callback_hint)

    def test_tc08_lookalike_sender_domains_are_flagged(self):
        self.assertEqual(registrable_domain("anphat.vn.secure-pay.com"), "secure-pay.com")
        self.assertEqual(registrable_domain("mail.anphat.com.vn"), "anphat.com.vn")
        for address in ("giamdoc@anphat-vn.com", "ceo@anphatt.vn", "ceo@anphat.vn.secure-pay.com"):
            self.assertTrue(is_lookalike_domain(address, "anphat.vn"), address)
        self.assertFalse(is_lookalike_domain("minh.tran@anphat.vn", "anphat.vn"))
        request = make_request("R08", "E01", "email", 80_000_000, sender_address="giamdoc@anphat-vn.com")
        self.assertTrue(any("giả dạng tên miền" in r for r in self.guard.submit(request).reasons))

    def test_tc09_email_failing_dmarc_is_flagged(self):
        request = make_request("R09", "E03", "email", 10_000_000, sender_address="nam.pham@anphat.vn",
                               metadata={"dmarc": "fail"})
        self.assertTrue(any("SPF/DKIM/DMARC" in r for r in self.guard.submit(request).reasons))

    def test_tc10_beneficiary_name_mismatch_is_flagged(self):
        request = make_request("R10", "E03", "portal_signed", 10_000_000, name="NGUYEN VAN K")
        request.signature = self.devices["E03"].sign_request(request)
        decision = self.guard.submit(request)
        self.assertNotEqual(decision.action, ALLOW)
        self.assertTrue(any("không khớp" in r for r in decision.reasons))

    def test_tc11_unknown_requester_is_denied(self):
        request = make_request("R11", "E99", "email", 5_000_000)
        self.assertEqual(self.guard.submit(request).action, DENY)

    # ===================== SỬA ĐỔI / DÙNG SAI NGỮ CẢNH =====================
    def test_tc12_signed_request_modified_in_transit_is_denied(self):
        request = make_request("R12", "E03", "portal_signed", 12_000_000)
        request.signature = self.devices["E03"].sign_request(request)
        request.amount = 120_000_000                    # MITM sửa số tiền sau khi ký
        decision = self.guard.submit(request)
        self.assertEqual(decision.action, DENY)
        self.assertTrue(any("chữ ký thiết bị không hợp lệ" in r for r in decision.reasons))

    def test_tc13_changing_beneficiary_after_verification_blocks_execution(self):
        request = make_request("R13", "E03", "email", 20_000_000, sender_address="nam.pham@anphat.vn")
        self.guard.submit(request)
        self.pass_oob(request)
        request.beneficiary_account = NEW_ACCOUNT      # "Anh đổi số tài khoản nhé" sau khi đã xác minh
        with self.assertRaisesRegex(VerificationError, "đã bị sửa"):
            self.guard.execute("R13", WORK_TIME)

    def test_tc14_replayed_challenge_response_is_rejected(self):
        request = make_request("R14", "E03", "email", 20_000_000, sender_address="nam.pham@anphat.vn")
        self.guard.submit(request)
        challenge = self.pass_oob(request)
        with self.assertRaisesRegex(VerificationError, "replay"):
            self.guard.submit_challenge_response("R14", challenge.nonce, self.devices["E03"].confirm(challenge), WORK_TIME)

    def test_tc15_expired_challenge_is_rejected(self):
        request = make_request("R15", "E03", "email", 20_000_000, sender_address="nam.pham@anphat.vn")
        self.guard.submit(request)
        challenge = self.guard.issue_challenge("R15", WORK_TIME)
        with self.assertRaisesRegex(VerificationError, "hết hạn"):
            self.guard.submit_challenge_response("R15", challenge.nonce, self.devices["E03"].confirm(challenge),
                                                 WORK_TIME + timedelta(minutes=6))

    def test_tc16_confirmation_for_one_request_cannot_be_reused_for_another(self):
        small = make_request("R16a", "E01", "email", 20_000_000, sender_address="minh.tran@anphat.vn")
        large = self.deepfake_ceo_request("R16b")
        self.guard.submit(small)
        self.guard.submit(large)
        challenge = self.guard.issue_challenge("R16a", WORK_TIME)
        signature = self.devices["E01"].confirm(challenge)     # CEO thật xác nhận giao dịch nhỏ
        with self.assertRaisesRegex(VerificationError, "giao dịch khác"):
            self.guard.submit_challenge_response("R16b", challenge.nonce, signature, WORK_TIME)

    # ===================== CHIẾM TÀI KHOẢN / PHÂN QUYỀN =====================
    def test_tc17_compromised_ceo_mailbox_cannot_complete_transfer(self):
        # Hộp thư thật của giám đốc bị chiếm: đúng tên miền, DMARC pass - vẫn không đủ để chuyển tiền.
        request = make_request("R17", "E01", "email", 180_000_000, NEW_ACCOUNT, "CONG TY TNHH HOANG KIM",
                               "Thanh toán gấp hợp đồng mới", sender_address="minh.tran@anphat.vn",
                               metadata={"dmarc": "pass"})
        decision = self.guard.submit(request)
        self.assertIn(decision.action, (STEP_UP, DUAL_APPROVAL))
        challenge = self.guard.issue_challenge("R17", WORK_TIME)
        with self.assertRaises(VerificationError):
            self.guard.submit_challenge_response("R17", challenge.nonce, attacker_device("E01").confirm(challenge), WORK_TIME)
        with self.assertRaises(VerificationError):
            self.guard.execute("R17", WORK_TIME + timedelta(hours=1))

    def test_tc18_self_approval_and_unauthorized_approver_are_rejected(self):
        request = make_request("R18", "E01", "video_call", 300_000_000, NEW_ACCOUNT, "CONG TY TNHH THIET BI MOI")
        self.guard.submit(request)
        with self.assertRaisesRegex(VerificationError, "tự phê duyệt"):
            self.guard.approve("R18", "E01", self.devices["E01"].approve(request))
        with self.assertRaisesRegex(VerificationError, "không có quyền"):
            self.guard.approve("R18", "E04", self.devices["E04"].approve(request))

    def test_tc19_approval_signed_for_old_amount_is_invalid(self):
        request = make_request("R19", "E01", "video_call", 300_000_000, NEW_ACCOUNT, "CONG TY TNHH THIET BI MOI")
        self.guard.submit(request)
        signature = self.devices["E02"].approve(request)
        request.amount = 900_000_000
        with self.assertRaisesRegex(VerificationError, "không khớp giao dịch"):
            self.guard.approve("R19", "E02", signature)

    def test_tc20_challenge_spam_is_limited_mfa_fatigue(self):
        request = self.deepfake_ceo_request()
        self.guard.submit(request)
        for _ in range(3):
            self.guard.issue_challenge(request.request_id, NIGHT_TIME)
        with self.assertRaisesRegex(VerificationError, "MFA fatigue"):
            self.guard.issue_challenge(request.request_id, NIGHT_TIME)
        self.assertIn("challenge_limit_reached", self.guard.audit.events())

    # ===================== TOÀN VẸN NHẬT KÝ & MẬT MÃ =====================
    def test_tc21_tampered_audit_log_is_detected(self):
        request = make_request("R21", "E03", "email", 20_000_000, sender_address="nam.pham@anphat.vn")
        self.guard.submit(request)
        self.pass_oob(request)
        self.guard.execute("R21", WORK_TIME)
        self.assertEqual(self.guard.audit.verify_chain(), (True, None))
        entry = self.guard.audit.entries[1]
        entry["data"]["sent_to"] = "0987654321"           # kẻ gian sửa log để che dấu vết
        content = {k: entry[k] for k in ("seq", "event", "data", "prev")}
        entry["hash"] = hashlib.sha256(json.dumps(content, sort_keys=True, ensure_ascii=False).encode()).hexdigest()
        self.assertEqual(self.guard.audit.verify_chain(), (False, 1))   # không có khoá HMAC nên không giả được

    def test_tc22_ed25519_matches_rfc8032_test_vector(self):
        secret = bytes.fromhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
        public = crypto.public_key(secret)
        self.assertEqual(public.hex(), "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
        signature = crypto.sign(secret)
        self.assertTrue(signature.startswith("e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bac"))
        self.assertTrue(crypto.verify(public, signature))
        self.assertFalse(crypto.verify(public, signature, "tampered"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
