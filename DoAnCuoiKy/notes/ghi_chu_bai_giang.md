# Ghi chú bài giảng dùng cho đồ án VeriGuard

## Bài 3 – Quản trị rủi ro & kiến trúc phòng thủ (text)
- Chuỗi: Asset → Threat → Vulnerability → Risk → Attack Chain → Control → Detect • Respond • Recover
- CIA (Confidentiality/Integrity/Availability) bảo vệ điều gì; AAA (Authentication-MFA / Authorization-RBAC / Accounting-Audit Log) kiểm soát ai làm gì
- Risk = Likelihood × Impact, ma trận 3×3 (ví dụ 3×3=9 Cao)
- Attack surface; bẻ gãy chuỗi tấn công tại nhiều điểm (Phishing→Mail filter, Cướp token→IAM/MFA, ...); "Không một control đơn lẻ đủ mạnh"
- Defense-in-Depth: Identity / Network / Host / App-API / Data + Detect (Logs+SIEM)
- NIST CSF 2.0: Govern, Identify, Protect, Detect, Respond, Recover
- Incident breakdown: Admin bị chiếm qua phishing (email giả, thiếu MFA, phiên quá dài...)
- Risk & Control Matrix: Asset | Vulnerability | Threat | Risk | Prevent | Detect
- Architect mindset: Xác định tài sản → Đánh giá rủi ro → Thiết kế kiểm soát → Xây dựng phát hiện → Chuẩn bị khôi phục
- Câu hỏi thảo luận tuần 3: Attack Chain → Control → Detect; chọn 3 biện pháp quan trọng nhất và giải thích ưu tiên

## Bài 4 – Kiến trúc mạng & phân vùng (text)
- Zones: Internet / DMZ / LAN / Server-Data / MGMT; VLAN/subnet; segmentation, micro-segmentation
- Controls: Firewall/NGFW, ACL (Source→Destination→Service→Action), WAF, IDS/IPS, VPN, NAC, egress filtering
- North-south & east-west; "deny by default chỉ có ý nghĩa khi biết chính xác luồng nào cần được phép"
- "Không có luồng nào tồn tại chỉ vì nó đang tồn tại."
- Deliverable: sơ đồ zone, danh sách luồng được phép, control tương ứng, 1–2 rủi ro nếu bỏ một lớp, "Nếu một máy nội bộ bị chiếm, attacker còn đi được tới đâu?"
- Khung trình bày: Asset/Attack Surface → Zone/Segmentation → Allowed Flows → Security Controls → Failure/Residual Risk

## Bài 5 – IAM: case Umbrella (docx)
- Thẻ hợp lệ nhưng không xác thực được khuôn mặt vẫn mở cửa; tài khoản người đã nghỉ 3 tháng vẫn hoạt động; mật khẩu yếu không MFA; SSO lan quyền; ACL trực tiếp trên file; tài khoản dùng chung; service account Domain Admin; session 24h

## Tuần 6 – Zero Trust (bài đọc Security Now)
- [SN1068] Gibson: "assume that authentication doesn't work ... take the responsibility of what happens if it fails"
- [SN1068] intro: "policies built on assumptions instead of verification"
- [SN1068] "it only takes one mistake from one employee one time"; đào tạo cần nhưng "insufficient because mistakes can still happen"
- [SN1068] Leo lo email hóa đơn giả tới phòng kế toán: "let's pay that invoice. How do you control that?"
- [SN1068] Scattered Lapsus$ Hunters thuê người gọi điện social engineering bằng giọng nữ (500–1000 USD), giả tiếng em bé khóc để SIM swap
- [SN1068] "what happens if any endpoint in the enterprise is malicious?"; continuously reauthenticate; least privilege khó triển khai; "It's layers"
- [SN1068] whitelist not blacklist; app whitelisting "powerful ... also really painful" (trade-off)
- [SN1066] TNO "Trust No One"; malicious server model; integrity chỉ từng field → cut-and-paste attack (liên hệ: ký toàn bộ digest giao dịch)
- [SN1066] Figure Technology bị social engineering, 967.200 khách hàng lộ dữ liệu (HIBP), chiến dịch nhắm khách hàng Okta SSO
- [SN1066] ClickFix 53% malware loader 2025 (Huntress); mật khẩu do LLM sinh "trông mạnh nhưng không an toàn"
- Không tài liệu nào nói trực tiếp deepfake → không gán.

## Tuần 7 – Bảo mật vật lý & thiết bị (text)
- Mối đe dọa con người: giả danh kỹ thuật viên, nội gián; vận hành: không thu hồi quyền
- Sinh trắc học: thuận tiện nhưng có rủi ro giả mạo; "Xác thực ≠ ủy quyền"
- Quy trình: Đăng ký → Xác thực → Kiểm soát vùng → Ghi nhận → Thu hồi
- Edge AI camera: "chỉ là cảnh báo hỗ trợ" (→ bộ phát hiện deepfake chỉ là tín hiệu phụ)
- Email Security Gateway: SPF/DKIM/DMARC
- TPM/Secure Element bảo vệ khóa/định danh thiết bị; HSM cho ký số, giao dịch nhạy cảm, khóa gốc; PQC/crypto agility
- "Một kiểm soát tốt cần có chủ sở hữu, cách kiểm tra và bằng chứng vận hành" (bảng Rủi ro | Kiểm soát | Bằng chứng)
- Backup: offline/immutable, kiểm thử phục hồi
- Zero Trust: không cấp quyền chỉ dựa vào vị trí mạng; "Mới không đồng nghĩa phù hợp"

## TH2 – Phân tích URL
- Registrable domain đọc từ phải sang trái (microflice365.com, không phải microsoft.com); redirect tới domain hợp lệ không làm URL ban đầu đáng tin; không đăng nhập qua link — tự mở bằng bookmark (→ tương tự: không gọi lại số do người gửi cung cấp)

## TH3 – SOC SHIFT
- Detector brute-force/spray, hash integrity, báo cáo sự cố 5 mục, không kết luận quá mức, MITRE T1110

## Bài 1 – Tổng quan (ảnh slide; số slide = thứ tự file)
- S2 vòng Tài sản / Mối đe dọa / Lỗ hổng / Biện pháp; câu hỏi cốt lõi "Điểm yếu nào có thể biến thành sự cố thật — và hệ thống cần kiểm soát nó ở đâu?"
- S3 Phương trình rủi ro: Tài sản có giá trị + Cấu hình & Môi trường yếu + Lỗi con người = Cơ hội khai thác
- S4 Lỗ hổng 4 tầng: Ứng dụng / Hệ thống / Mạng / Con người & Quy trình ("quy trình vận hành lỏng lẻo")
- S5 Ma trận tấn công: Đánh cắp, Giả mạo (Spoofing), Chặn-Xen giữa (MITM), DoS/DDoS, Tấn công dịch vụ, Tấn công ứng dụng
- S6 MITM phòng thủ: Yêu cầu Xác thực; Mã hóa toàn trình; Bảo vệ phiên; Giám sát bất thường
- S8 Chuỗi hành động: Khảo sát → Xác định → Khai thác → Duy trì → Tác động; "Có thể phát hiện và ngăn chặn ở bất kỳ điểm nào trong chuỗi"
- S9 Phòng thủ nhiều lớp: Người dùng / Ứng dụng / Máy chủ-Endpoint / Mạng / Giám sát bao trùm
- S10 "Phát hiện ≠ Phòng chống"; S14 yêu cầu ≥1 Phát hiện + ≥1 Phòng chống
- S12 tình huống email giả → nhập tài khoản → đăng nhập bất thường
- S15 "Chuyển tư duy từ bảo vệ đường truyền sang bảo vệ chính dữ liệu"
- Bài 1 KHÔNG có CIA (CIA ở Bài 3)

## Bài 5 – IAM (ảnh slide)
- S2 AAA mở rộng: Identification (Ai? "ID chưa phải là Xác thực") / Authentication (Đúng người?) / Authorization (Được làm gì?) / Accounting (Có bằng chứng gì?)
- S3 Vòng đời IAM: Tạo mới → Xác minh → Cấp quyền → Sử dụng → Rà soát → Thu hồi; "Mọi quyền truy cập phải có owner, thời hạn cụ thể, hoặc điều kiện rà soát định kỳ"
- S4 Yếu tố: Biết / Có / Là / Bối cảnh (Device, IP, Location); Salt + KDF (Argon2/Bcrypt) + rate limiting; "Hash không đồng nghĩa với An toàn"
- S5 "MFA phải kết hợp các yếu tố độc lập"; MFA Fatigue (push spam); Recovery yếu; Thiếu Re-Auth cho thao tác nhạy cảm (đổi mật khẩu, chuyển tiền)
- S6 Passkeys/FIDO2: Private key trên thiết bị, Public key trên server, Cryptographic Challenge/Response, Origin Binding (RP ID)
- S7 SSO blast radius; OAuth 2.0 là ủy quyền, KHÔNG phải xác thực; S8 OIDC ID token vs Access token; Auth Code + PKCE
- S9 RBAC (role explosion) / ABAC (Role+Time+Device+Resource) / ACL; "RBAC làm nền tảng, ABAC cho ngữ cảnh, ACL cho ngoại lệ"
- S10 Least privilege, Blast Radius; PAM (không admin thường trực, Credential Broker, tạm thời, ghi hình/audit)
- S11 Service accounts: secret riêng, least privilege, rotate
- S12 Session: Issue → Use → Re-Auth → Rotate → Expire/Revoke; triggers: đổi IP/Device, re-auth khi thanh toán
- S13 Kiến trúc mẫu Cổng thông tin Đại học (IdP, API Gateway → Policy Engine, PAM Vault)
- S14 Checklist: IDENTITY, AUTHN, FEDERATION, AUTHZ, PRIVILEGE, SESSIONS, AUDIT
- S15 refs: NIST SP 800-63-4/B-4, OWASP Authentication & Session Management, IETF RFC 9700, W3C WebAuthn
