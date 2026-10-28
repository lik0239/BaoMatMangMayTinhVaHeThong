"""Nhật ký kiểm toán (Accounting - AAA) dạng chuỗi băm có khoá.

"Hash không tự xác thực" (Tuần 8): chuỗi SHA-256 thuần có thể bị kẻ có quyền ghi tính lại toàn bộ.
Vì vậy mỗi mắt xích là HMAC-SHA256 với khoá kiểm toán lưu tách biệt (Secret Manager/KMS), không nằm
cùng dữ liệu nhật ký. Sửa, xoá hay chèn một bản ghi đều làm gãy chuỗi.
"""
import hashlib
import hmac
import json

GENESIS = "0" * 64


class AuditLog:
    def __init__(self, audit_key: bytes):
        self._key = audit_key
        self.entries = []

    def append(self, event, **data):
        previous_hash = self.entries[-1]["hash"] if self.entries else GENESIS
        body = {"seq": len(self.entries), "event": event, "data": data, "prev": previous_hash}
        body["hash"] = self._mac(body)
        self.entries.append(body)
        return body

    def _mac(self, body):
        content = {k: body[k] for k in ("seq", "event", "data", "prev")}
        message = json.dumps(content, sort_keys=True, ensure_ascii=False, default=str).encode()
        return hmac.new(self._key, message, hashlib.sha256).hexdigest()

    def verify_chain(self):
        """Trả về (True, None) nếu toàn vẹn, ngược lại (False, seq đầu tiên bị hỏng)."""
        previous_hash = GENESIS
        for index, entry in enumerate(self.entries):
            if (entry["seq"] != index or entry["prev"] != previous_hash
                    or not hmac.compare_digest(entry["hash"], self._mac(entry))):
                return False, index
            previous_hash = entry["hash"]
        return True, None

    def events(self):
        return [entry["event"] for entry in self.entries]
