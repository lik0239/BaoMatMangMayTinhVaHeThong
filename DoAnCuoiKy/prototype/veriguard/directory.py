"""Danh bạ tin cậy: nguồn sự thật duy nhất về danh tính, số điện thoại và người thụ hưởng.

Nguyên tắc: thông tin liên lạc dùng để xác minh luôn lấy từ đây, không bao giờ lấy từ chính yêu cầu.
"""
from .models import Employee


class TrustedDirectory:
    def __init__(self, company_domain):
        self.company_domain = company_domain
        self._employees = {}
        self._beneficiaries = {}   # account -> tên chủ tài khoản đã xác minh

    def add_employee(self, employee: Employee):
        self._employees[employee.employee_id] = employee

    def get(self, employee_id):
        return self._employees.get(employee_id)

    def approvers(self):
        return [e for e in self._employees.values() if e.can_approve]

    def add_beneficiary(self, account, verified_name):
        self._beneficiaries[account] = verified_name

    def beneficiary_name(self, account):
        return self._beneficiaries.get(account)

    def is_known_beneficiary(self, account):
        return account in self._beneficiaries
