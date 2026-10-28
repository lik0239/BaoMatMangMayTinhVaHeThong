"""Sinh các sơ đồ của đồ án VeriGuard dưới dạng HTML/SVG (sau đó chụp PNG bằng Edge headless)."""
import sys
from html import escape
from pathlib import Path

OUT = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(__file__).parent
FONT = "Segoe UI, Arial, sans-serif"
INK, MUTED = "#1d2733", "#5b6776"
BLUE, GREEN, RED, ORANGE, PURPLE = "#1f5fa8", "#1e7d4f", "#b3261e", "#b26a00", "#6a3fb5"


def text(x, y, lines, size=17, weight="normal", color=INK, anchor="start", line_gap=1.3):
    if isinstance(lines, str):
        lines = [lines]
    spans = "".join(
        f'<tspan x="{x}" dy="{0 if i == 0 else size * line_gap}">{escape(line)}</tspan>' for i, line in enumerate(lines))
    return (f'<text x="{x}" y="{y}" font-family="{FONT}" font-size="{size}" font-weight="{weight}" '
            f'fill="{color}" text-anchor="{anchor}">{spans}</text>')


def box(x, y, w, h, title, lines=(), stroke=BLUE, fill="#ffffff", title_size=18, size=15, dash=False):
    d = ' stroke-dasharray="7 5"' if dash else ""
    parts = [f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="10" fill="{fill}" stroke="{stroke}" stroke-width="2.2"{d}/>',
             text(x + 14, y + 27, title, title_size, "600", stroke)]
    if lines:
        parts.append(text(x + 14, y + 27 + title_size * 1.35, list(lines), size, color=INK))
    return "".join(parts)


def zone(x, y, w, h, label, fill, stroke):
    return (f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="14" fill="{fill}" stroke="{stroke}" '
            f'stroke-width="1.5" stroke-dasharray="10 6"/>' + text(x + 14, y + 26, label, 16, "700", stroke))


def arrow(points, color=INK, dash=False, label=None, label_at=None, width=2.2, label_color=None):
    d = " ".join(f"{'M' if i == 0 else 'L'}{px},{py}" for i, (px, py) in enumerate(points))
    dash_attr = ' stroke-dasharray="7 5"' if dash else ""
    marker = {INK: "a-ink", RED: "a-red", GREEN: "a-green", PURPLE: "a-purple", BLUE: "a-blue"}[color]
    out = f'<path d="{d}" fill="none" stroke="{color}" stroke-width="{width}"{dash_attr} marker-end="url(#{marker})"/>'
    if label:
        lx, ly = label_at
        out += text(lx, ly, label, 14, "600", label_color or color, "middle")
    return out


def defs():
    markers = "".join(
        f'<marker id="{name}" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="8" markerHeight="8" orient="auto-start-reverse">'
        f'<path d="M0,0 L10,5 L0,10 z" fill="{color}"/></marker>'
        for name, color in (("a-ink", INK), ("a-red", RED), ("a-green", GREEN), ("a-purple", PURPLE), ("a-blue", BLUE)))
    return f"<defs>{markers}</defs>"


def page(name, width, height, body):
    svg = (f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}">'
           f'<rect width="100%" height="100%" fill="#ffffff"/>{defs()}{body}</svg>')
    html = (f'<!doctype html><html><head><meta charset="utf-8"><style>html,body{{margin:0;padding:0;background:#fff}}'
            f'svg{{display:block}}</style></head><body>{svg}</body></html>')
    (OUT / f"{name}.html").write_text(html, encoding="utf-8")
    (OUT / f"{name}.svg").write_text(svg, encoding="utf-8")


# ---------------------------------------------------------------- Hình 1: kiến trúc
def architecture():
    b = []
    b.append(text(800, 40, "Kiến trúc VeriGuard theo vùng (Internet → DMZ → App → Data, MGMT) và mô hình PDP/PEP", 22, "700", INK, "middle"))
    b.append(zone(20, 70, 290, 880, "ZONE A · INTERNET (không tin cậy)", "#fdf0ee", RED))
    b.append(zone(340, 70, 260, 880, "ZONE B · DMZ", "#fff6e6", ORANGE))
    b.append(zone(630, 70, 430, 880, "ZONE C · APP – VeriGuard", "#edf4fc", BLUE))
    b.append(zone(1090, 70, 270, 520, "ZONE D · DATA", "#ecf7f1", GREEN))
    b.append(zone(1090, 650, 270, 300, "ZONE E · MGMT / SECRETS", "#f4effb", PURPLE))
    b.append(zone(1390, 70, 190, 880, "BÊN NGOÀI", "#f4f4f4", MUTED))

    b.append(box(40, 110, 250, 90, "Email", ["tên miền / nội dung", "có thể giả mạo"], ORANGE))
    b.append(box(40, 215, 250, 90, "Chat / Zalo", ["tài khoản có thể", "bị chiếm"], ORANGE))
    b.append(box(40, 320, 250, 90, "Cuộc gọi / Video call", ["giọng nói, khuôn mặt", "có thể là deepfake"], ORANGE))
    b.append(box(40, 470, 250, 115, "Kẻ tấn công", ["deepfake giám đốc, email", "tên miền nhái, hộp thư", "bị chiếm, đổi số tài khoản"], RED, "#fff7f6"))
    b.append(box(40, 680, 250, 160, "Thiết bị đã đăng ký", ["App VeriGuard trên điện thoại", "khoá riêng Ed25519 trong", "Secure Element (không rời", "thiết bị) · hiển thị số tiền,", "người nhận trước khi ký"], GREEN, "#f3fbf6"))

    b.append(box(360, 110, 220, 120, "Email Security GW", ["SPF / DKIM / DMARC", "chặn tên miền nhái", "(đọc từ phải sang trái)"], ORANGE))
    b.append(box(360, 300, 220, 140, "API Gateway + WAF", ["TLS (in transit)", "rate limit", "xác thực phiên +", "re-auth khi chuyển tiền"], ORANGE))
    b.append(box(360, 690, 220, 140, "Cổng xác minh", ["push thử thách tới", "thiết bị đã đăng ký", "nhận phản hồi đã ký"], ORANGE))

    b.append(box(650, 105, 390, 85, "Tiếp nhận yêu cầu", ["chuẩn hoá + tính digest SHA-256 của", "(người yêu cầu, số tiền, TK, tên nhận)"]))
    b.append(box(650, 215, 390, 175, "PDP · Policy Decision Point", ["Risk Engine (Context Signals): kênh,", "người thụ hưởng mới, hạn mức, giờ,", "ngôn ngữ thúc ép, tên miền nhái, DMARC,", "deepfake score (chỉ tín hiệu phụ)", "→ ALLOW / STEP-UP / DUAL / DENY"], BLUE, "#f7fbff"))
    b.append(box(650, 420, 185, 135, "Xác minh OOB", ["nonce CSPRNG", "hết hạn 5 phút", "dùng 1 lần", "tối đa 3 lần gửi"]))
    b.append(box(855, 420, 185, 135, "Phê duyệt kép", ["người duyệt độc lập", "không tự duyệt", "ký Ed25519 trên", "digest giao dịch"]))
    b.append(box(650, 590, 390, 125, "PEP · Policy Enforcement Point", ["digest có đổi không? đủ bước chưa?", "hết thời gian chờ 30' (TK mới) chưa?", "→ mới phát lệnh chuyển tiền"], BLUE, "#f7fbff"))
    b.append(box(650, 760, 390, 90, "Cảnh báo SOC", ["DENY · chữ ký sai · 'Không phải tôi'", "spam xác minh (MFA fatigue)"], RED, "#fff7f6"))

    b.append(box(1110, 105, 230, 150, "Danh bạ tin cậy", ["khoá công khai thiết bị", "số ĐT đã xác minh", "hạn mức, quyền duyệt", "người thụ hưởng đã XM"], GREEN))
    b.append(box(1110, 280, 230, 105, "CSDL giao dịch", ["mã hoá at rest", "(AES-GCM, envelope)"], GREEN))
    b.append(box(1110, 410, 230, 145, "Audit Log", ["chuỗi HMAC-SHA256", "append-only (WORM)", "không ghi giá trị khoá"], GREEN))
    b.append(box(1110, 690, 230, 115, "KMS / HSM", ["khoá HMAC audit, KEK", "không rời phần cứng", "xoay vòng, thu hồi"], PURPLE))
    b.append(box(1110, 822, 230, 110, "PAM", ["quản trị tạm thời", "(đăng ký thiết bị,", "sửa danh bạ) có log"], PURPLE))
    b.append(box(1405, 545, 160, 160, "Ngân hàng", ["Core banking", "API chuyển tiền", "mTLS + ký lệnh"], MUTED))

    b.append(arrow([(290, 160), (360, 160)]))
    b.append(arrow([(290, 260), (318, 260), (318, 350), (360, 350)]))
    b.append(arrow([(290, 365), (332, 365), (332, 400), (360, 400)]))
    b.append(arrow([(165, 470), (165, 412)], RED, True, "giả mạo", (205, 450)))
    b.append(arrow([(580, 160), (650, 160)]))
    b.append(arrow([(580, 370), (612, 370), (612, 178), (650, 178)]))
    b.append(arrow([(845, 190), (845, 215)]))
    b.append(arrow([(742, 390), (742, 420)]))
    b.append(arrow([(947, 390), (947, 420)]))
    b.append(arrow([(1040, 260), (1075, 260), (1075, 180), (1110, 180)], GREEN, False, "tra cứu", (1075, 290)))
    b.append(arrow([(650, 490), (622, 490), (622, 725), (580, 725)], BLUE, False))
    b.append(text(606, 600, ["push", "thử", "thách"], 13, "600", BLUE, "end"))
    b.append(arrow([(360, 725), (290, 725)], BLUE))
    b.append(arrow([(290, 800), (360, 800)], GREEN))
    b.append(text(325, 822, ["chữ ký", "Ed25519"], 13, "600", GREEN, "middle", 1.15))
    b.append(arrow([(580, 800), (636, 800), (636, 535), (650, 535)], GREEN))
    b.append(arrow([(742, 555), (742, 590)]))
    b.append(arrow([(947, 555), (947, 590)]))
    b.append(arrow([(1040, 622), (1405, 622)], INK, False, "lệnh đã đủ điều kiện", (1250, 612)))
    b.append(arrow([(845, 715), (845, 760)], RED))
    b.append(arrow([(1040, 480), (1110, 480)], GREEN, True))
    b.append(text(1075, 502, ["mọi", "sự kiện"], 13, "600", GREEN, "middle", 1.15))
    b.append(arrow([(1340, 747), (1376, 747), (1376, 500), (1340, 500)], PURPLE, True))
    page("hinh1_kien_truc", 1600, 970, "".join(b))


# ---------------------------------------------------------------- Hình 2: sequence
def sequence():
    lanes = [("Kẻ gian\n(deepfake GĐ)", RED), ("Kế toán\n(Phạm Nam)", INK), ("VeriGuard\nPDP", BLUE),
             ("Thiết bị đã đăng ký\ncủa Giám đốc thật", GREEN), ("PEP /\nNgân hàng", BLUE), ("Audit Log\n(HMAC)", PURPLE)]
    width, top, gap = 1600, 70, 250
    xs = [140 + i * 264 for i in range(len(lanes))]
    b = [text(width / 2, 38, "Luồng xử lý kịch bản deepfake: video call 'Giám đốc' yêu cầu chuyển gấp 450 triệu", 22, "700", INK, "middle")]
    for x, (name, color) in zip(xs, lanes):
        b.append(f'<rect x="{x - 105}" y="{top}" width="210" height="62" rx="10" fill="#fff" stroke="{color}" stroke-width="2.2"/>')
        b.append(text(x, top + 26, name.split("\n"), 16, "700", color, "middle", 1.2))
        b.append(f'<line x1="{x}" y1="{top + 62}" x2="{x}" y2="1030" stroke="#b9c2cc" stroke-width="2" stroke-dasharray="6 6"/>')

    def msg(i, j, y, label, color=INK, dash=False, note=None):
        x1, x2 = xs[i], xs[j]
        off = 8 if x2 > x1 else -8
        b.append(arrow([(x1, y), (x2 - off, y)], color, dash))
        b.append(text((x1 + x2) / 2, y - 10, label, 15, "600", color, "middle"))

    def self_note(i, y, lines, color=BLUE, fill="#f7fbff", w=330):
        x = xs[i]
        h = 22 * len(lines) + 16
        b.append(f'<rect x="{x - w / 2}" y="{y}" width="{w}" height="{h}" rx="8" fill="{fill}" stroke="{color}" stroke-width="1.8"/>')
        b.append(text(x, y + 23, lines, 15, "normal", INK, "middle", 1.45))
        return y + h

    y = 190
    msg(0, 1, y, "① Video call 'GĐ': chuyển gấp 450tr đặt cọc, giữ bí mật, đừng gọi lại", RED)
    y += 60
    msg(1, 2, y, "② Nhập yêu cầu (kênh video_call, TK mới 9704…)")
    y += 25
    y = self_note(2, y, ["③ Chấm điểm: 30 kênh + 25 TK mới + 15 số tiền", "+ 15 thúc ép + 10 số gọi lại = 95", "→ DUAL_APPROVAL + chờ 30 phút"]) + 45
    msg(2, 3, y, "④ Thử thách (nonce, digest, 450tr → NGUYEN VAN K) tới SĐT trong danh bạ", GREEN)
    y += 55
    msg(0, 2, y, "⑤ Phản hồi ký bằng khoá của kẻ gian", RED, True)
    y += 20
    y = self_note(2, y, ["✗ Ed25519 verify thất bại với khoá công khai", "đã đăng ký → challenge_failed"], RED, "#fff7f6") + 45
    msg(3, 2, y, "⑥ GĐ thật bấm 'Không phải tôi' → cảnh báo giả danh", GREEN)
    y += 60
    msg(1, 4, y, "⑦ Kế toán bị thúc ép, bấm 'Chuyển' lần nữa")
    y += 20
    y = self_note(4, y, ["✗ PEP CHẶN: giao dịch đã bị từ chối,", "chưa có OOB + phê duyệt độc lập"], RED, "#fff7f6", 300) + 45
    for i, label in ((2, "ghi ②③⑤⑥"), (4, "ghi ⑦")):
        msg(i, 5, y, label, PURPLE, True)
        y += 45
    b.append(text(xs[0] - 100, y + 40, "Điểm mấu chốt: hệ thống không dựa vào việc khuôn mặt/giọng nói 'trông thật'. Căn cứ tin cậy duy nhất là chữ ký "
                  "từ khoá riêng trên thiết bị đã đăng ký,", 16, "normal", MUTED))
    b.append(text(xs[0] - 100, y + 64, "gắn với digest giao dịch; kênh liên lạc để xác minh lấy từ danh bạ tin cậy chứ không lấy từ yêu cầu.", 16, "normal", MUTED))
    page("hinh2_luong_deepfake", width, int(y + 95), "".join(b))


# ---------------------------------------------------------------- Hình 3: chuỗi tấn công
def attack_chain():
    steps = [
        ("1. Khảo sát", "Thu thập video, giọng nói GĐ trên mạng; sơ đồ tổ chức, tên kế toán",
         ["Hạn chế công khai thông tin nội bộ", "Đào tạo nhận diện lừa đảo"], ["—"]),
        ("2. Xác định", "Tìm người có quyền chuyển tiền, quy trình duyệt chỉ dựa vào 1 người",
         ["Mọi lệnh bắt buộc qua VeriGuard", "Hạn mức theo vai trò (RBAC/ABAC)"], ["—"]),
        ("3. Khai thác", "Video call deepfake, email tên miền nhái, hộp thư thật bị chiếm",
         ["Không tin kênh: voice/video/email/chat", "= lời khai, luôn STEP-UP trở lên"], ["PDP chấm điểm ngữ cảnh", "DMARC fail, tên miền nhái"]),
        ("4. Duy trì", "Thúc ép, gửi lại yêu cầu, 'đổi số TK', spam xác nhận",
         ["Phê duyệt gắn digest giao dịch", "Nonce dùng 1 lần, hết hạn 5'"], ["Giới hạn 3 lần thử thách", "Cảnh báo MFA fatigue"]),
        ("5. Tác động", "Tiền rời tài khoản công ty",
         ["PEP: OOB + phê duyệt kép", "Chờ 30' với người thụ hưởng mới"], ["Audit log HMAC, cảnh báo SOC", "Recover: báo NH chặn trong 30'"]),
    ]
    width, col_w, x0 = 1600, 296, 30
    b = [text(width / 2, 40, "Chuỗi tấn công lừa đảo chuyển tiền (Bài 1) và điểm chặn của VeriGuard", 22, "700", INK, "middle")]
    for i, (title, desc, prevent, detect) in enumerate(steps):
        x = x0 + i * (col_w + 12)
        b.append(f'<path d="M{x},70 L{x + col_w - 22},70 L{x + col_w},115 L{x + col_w - 22},160 L{x},160 L{x + 22},115 z" fill="{RED if i < 3 else "#8f1d17"}" opacity="{0.75 + i * 0.05}"/>')
        b.append(text(x + col_w / 2 + 6, 122, title, 20, "700", "#ffffff", "middle"))
        b.append(f'<rect x="{x}" y="180" width="{col_w}" height="105" rx="10" fill="#fff7f6" stroke="{RED}" stroke-width="1.6"/>')
        b.append(text(x + 14, 208, _wrap(desc, 30), 15, "normal", INK))
        b.append(f'<rect x="{x}" y="320" width="{col_w}" height="120" rx="10" fill="#f3fbf6" stroke="{GREEN}" stroke-width="1.8"/>')
        b.append(text(x + 14, 348, ["PHÒNG CHỐNG"] , 14, "700", GREEN))
        b.append(text(x + 14, 374, prevent, 15, "normal", INK))
        b.append(f'<rect x="{x}" y="465" width="{col_w}" height="110" rx="10" fill="#f7fbff" stroke="{BLUE}" stroke-width="1.8"/>')
        b.append(text(x + 14, 493, ["PHÁT HIỆN / KHÔI PHỤC"], 14, "700", BLUE))
        b.append(text(x + 14, 519, detect, 15, "normal", INK))
    b.append(text(x0, 615, "“Có thể phát hiện và ngăn chặn ở bất kỳ điểm nào trong chuỗi — không cần chờ tới lúc mất dữ liệu.” (Bài 1)  ·  "
                  "Phát hiện ≠ Phòng chống: mỗi bước có ít nhất một lớp chặn.", 16, "normal", MUTED))
    page("hinh3_chuoi_tan_cong", width, 640, "".join(b))


def _wrap(sentence, limit):
    words, lines, current = sentence.split(), [], ""
    for word in words:
        if len(current) + len(word) + 1 > limit:
            lines.append(current)
            current = word
        else:
            current = f"{current} {word}".strip()
    return lines + [current]


# ---------------------------------------------------------------- Hình 4: ma trận rủi ro
def risk_matrix():
    risks = {(3, 3): ["R1 Deepfake giả danh GĐ"], (3, 2): ["R2 Email/hoá đơn giả (BEC)"],
             (2, 3): ["R3 Hộp thư thật bị chiếm", "R4 Đổi số TK sau xác minh"], (2, 2): ["R7 Spam xác nhận (MFA fatigue)"],
             (1, 3): ["R5 Nội bộ tự duyệt / lạm quyền", "R8 Mất điện thoại đã đăng ký"], (1, 2): ["R6 Sửa nhật ký xoá dấu vết"]}
    colors = {1: "#e3f3e8", 2: "#e3f3e8", 3: "#f8efc8", 4: "#f8efc8", 6: "#f9c9c2", 9: "#f2a49a"}
    cell, x0, y0 = 300, 210, 90
    b = [text(800, 40, "Ma trận rủi ro trước khi có VeriGuard: Rủi ro = Khả năng xảy ra × Mức tác động (Bài 3)", 22, "700", INK, "middle")]
    for likelihood in (3, 2, 1):
        for impact in (1, 2, 3):
            x, y = x0 + (impact - 1) * cell, y0 + (3 - likelihood) * 170
            score = likelihood * impact
            b.append(f'<rect x="{x}" y="{y}" width="{cell}" height="170" fill="{colors[score]}" stroke="#ffffff" stroke-width="4"/>')
            b.append(text(x + cell - 14, y + 30, str(score), 22, "700", "#7a2a22" if score >= 6 else MUTED, "end"))
            for k, label in enumerate(risks.get((likelihood, impact), [])):
                b.append(f'<rect x="{x + 12}" y="{y + 45 + k * 52}" width="{cell - 24}" height="42" rx="8" fill="#ffffff" stroke="{RED}" stroke-width="1.4"/>')
                b.append(text(x + 24, y + 72 + k * 52, label, 15, "600", INK))
        b.append(text(x0 - 20, y0 + (3 - likelihood) * 170 + 92, ["Cao (3)", "Trung bình (2)", "Thấp (1)"][3 - likelihood], 17, "600", INK, "end"))
    for impact, label in ((1, "Thấp (1)"), (2, "Trung bình (2)"), (3, "Cao (3)")):
        b.append(text(x0 + (impact - 1) * cell + cell / 2, y0 + 545, label, 17, "600", INK, "middle"))
    b.append(text(x0 + 1.5 * cell, y0 + 580, "MỨC TÁC ĐỘNG →", 18, "700", INK, "middle"))
    b.append(f'<text x="40" y="{y0 + 255}" font-family="{FONT}" font-size="18" font-weight="700" fill="{INK}" '
             f'transform="rotate(-90 40 {y0 + 255})" text-anchor="middle">KHẢ NĂNG XẢY RA →</text>')
    b.append(text(1140, 120, "Thang đo", 17, "700", INK))
    b.append(text(1140, 150, ["Khả năng: 1 hiếm · 2 có thể · 3 thường gặp", "Tác động: 1 nhỏ · 2 đáng kể ·", "   3 mất tiền lớn / khó thu hồi"], 16))
    b.append(text(1140, 250, "Màu", 17, "700", INK))
    b.append(text(1140, 280, ["xanh: 1–2 · vàng: 3–4", "đỏ: 6–9 (ưu tiên xử lý trước)"], 16))
    b.append(text(1140, 360, ["Rủi ro tồn dư sau kiểm soát:", "xem bảng Risk & Control Matrix"], 16, "normal", MUTED))
    page("hinh4_ma_tran_rui_ro", 1600, 700, "".join(b))


if __name__ == "__main__":
    architecture()
    sequence()
    attack_chain()
    risk_matrix()
    print("ok")
