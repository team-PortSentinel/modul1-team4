"""
취약점 분석 시스템 (풀 다크 · 2단 레이아웃 + PDF 보고서 + Nmap Scanner 연동)
"""

import html
import subprocess
import shutil
from io import BytesIO
from datetime import datetime
from collections import Counter

import streamlit as st
import plotly.graph_objects as go

from reportlab.lib.pagesizes import A4
from reportlab.lib.units import mm
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.cidfonts import UnicodeCIDFont

st.set_page_config(page_title="침투 테스트 지원 시스템", page_icon="🛡️", layout="wide")

# 한국어 PDF용 내장 폰트 (외부 폰트 다운로드 불필요)
pdfmetrics.registerFont(UnicodeCIDFont("HYSMyeongJo-Medium"))
KRFONT = "HYSMyeongJo-Medium"

ACCENT = "#2563eb"
RISK_RED, RISK_AMBER, RISK_GRAY = "#f87171", "#fbbf24", "#94a3b8"

st.markdown("""
<style>
.soc-sub { font-family:monospace; color:#38bdf8; font-size:13px; letter-spacing:1px; }
.sec-label { color:#94a3b8; font-size:13px; margin:4px 0 8px; }
.chatpanel { background:#0f1729; border:1px solid #1e2b45; border-radius:14px;
padding:14px 16px; min-height:330px; }
.chathead { display:flex; justify-content:space-between; color:#475569;
font-size:16px; border-bottom:1px solid #1e2b45; padding-bottom:10px; margin-bottom:14px; }
.bubble { font-size:13.5px; line-height:1.55; margin:12px 0; }
.bubble.bot { background:#16223b; border-left:3px solid #38bdf8; border-radius:0 10px 10px 0;
padding:10px 12px; color:#cbd5e1; max-width:88%; }
.bubble.bot .ic { color:#38bdf8; font-weight:700; }
.bubble.user { background:#1e3a5f; border-radius:10px 10px 4px 10px; padding:10px 12px;
color:#e2e8f0; max-width:82%; margin-left:auto; }
[data-testid="stTextArea"] textarea { background:#0a1120; color:#e2e8f0; border:1px solid #1e2b45; }
.ecard { background:#16223b; border:1px solid #1e2b45; border-radius:10px;
padding:9px 12px; margin-bottom:8px; display:flex; align-items:center; gap:10px;
color:#e2e8f0; font-size:13px; }
.ecard small { color:#64748b; }
[data-testid="stMetric"] { background:#0f1729; border:1px solid #1e2b45; border-radius:10px; padding:14px; }
.badge-kev { background:#3d1418; color:#fca5a5; padding:1px 8px; border-radius:20px; font-size:12px; }
.fix-box { background:#0d2438; border-left:3px solid #38bdf8; border-radius:0 6px 6px 0;
padding:10px 12px; color:#bae6fd; font-size:14px; line-height:1.55; margin-top:6px; }
</style>
""", unsafe_allow_html=True)


# ── 데이터 & 로직 ──────────────────────────────────────────────────────
SAMPLE_RESULT = [
    {"port": 80, "service": "Apache httpd", "version": "2.4.49", "cve_id": "CVE-2021-41773",
     "cvss": 7.5, "epss": 0.94, "kev": True, "predicted_risk": 0.89, "priority_rank": 1,
     "description": "경로 탐색 → 원격 코드 실행. 실제 공격에 활발히 쓰임.",
     "fix": "2.4.51 이상으로 즉시 업그레이드, mod_cgi 비활성화 검토"},
    {"port": 80, "service": "Apache httpd", "version": "2.4.49", "cve_id": "CVE-2021-42013",
     "cvss": 9.8, "epss": 0.91, "kev": True, "predicted_risk": 0.82, "priority_rank": 2,
     "description": "41773 패치 우회. 임의 파일 노출 및 RCE 가능.",
     "fix": "2.4.51 이상으로 업그레이드 (2.4.50 패치는 불완전)"},
    {"port": 22, "service": "OpenSSH", "version": "7.4", "cve_id": "CVE-2016-6210",
     "cvss": 5.9, "epss": 0.35, "kev": False, "predicted_risk": 0.54, "priority_rank": 3,
     "description": "응답 시간 차이로 사용자 존재 여부 추측 가능(정보 노출).",
     "fix": "OpenSSH 최신 버전으로 업그레이드"},
    {"port": 3306, "service": "MySQL", "version": "5.7.28", "cve_id": "CVE-2021-3711",
     "cvss": 6.5, "epss": 0.28, "kev": False, "predicted_risk": 0.47, "priority_rank": 4,
     "description": "연동 라이브러리 취약점으로 인한 서비스 거부 가능성.",
     "fix": "MySQL 및 OpenSSL 라이브러리 패치 적용"},
    {"port": 3306, "service": "MySQL", "version": "5.7.28", "cve_id": "CVE-2020-14812",
     "cvss": 4.9, "epss": 0.12, "kev": False, "predicted_risk": 0.31, "priority_rank": 5,
     "description": "권한 있는 사용자에 의한 부분적 서비스 영향.",
     "fix": "MySQL 5.7.32 이상으로 업그레이드"},
]


def analyze_scan(scan_text):
    # 실제 연동 시에는 여기서 Nmap 텍스트를 파싱(parser.py 연동)하고 모델 예측을 진행합니다.
    return SAMPLE_RESULT


def run_live_scan(target, options):
    """
    Nmap 실행 파일 존재 여부를 체크한 뒤, 백그라운드에서 Nmap 스캔을 가동하는 함수입니다.
    """
    if not shutil.which("nmap"):
        # 로컬 환경에 Nmap이 설치되어 있지 않은 경우 예시 시뮬레이션 결과를 반환합니다.
        return f"""# Nmap 7.92 scan initiated for simulated target: {target}
Nmap scan report for {target} (192.168.1.10)
Host is up (0.0021s latency).
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 7.4
80/tcp   open  http    Apache httpd 2.4.49
3306/tcp open  mysql   MySQL 5.7.28
# Nmap done -- 1 IP address scanned in 2.12 seconds"""

    try:
        # 안전한 파라미터 제어를 위해 리스트 형태로 명령어를 분리하여 샐행합니다.
        args = ["nmap"] + options.split() + [target]
        result = subprocess.run(args, capture_output=True, text=True, timeout=120, check=True)
        return result.stdout
    except subprocess.TimeoutExpired:
        return "Error: Nmap 스캔 시간이 초과되었습니다 (제한시간 120초)."
    except Exception as e:
        return f"Error: 스캔 실행 중 오류가 발생했습니다. ({str(e)})"


def generate_fix_with_ai(cve):
    return cve.get("fix", "대응방안 준비 중")


def severity(risk):
    if risk >= 0.7:
        return "High", RISK_RED
    if risk >= 0.4:
        return "Medium", RISK_AMBER
    return "Low", RISK_GRAY


# ── PDF 보고서 생성 ────────────────────────────────────────────────────
def build_pdf_report(cves):
    buf = BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4, topMargin=20 * mm, bottomMargin=18 * mm,
                            leftMargin=18 * mm, rightMargin=18 * mm)
    ss = getSampleStyleSheet()
    title = ParagraphStyle("t", parent=ss["Title"], fontName=KRFONT, fontSize=18)
    head = ParagraphStyle("h", parent=ss["Heading2"], fontName=KRFONT, fontSize=12,
                          textColor=colors.HexColor("#1e40af"))
    body = ParagraphStyle("b", parent=ss["Normal"], fontName=KRFONT, fontSize=10, leading=15)
    small = ParagraphStyle("s", parent=body, fontSize=9, textColor=colors.HexColor("#555555"))

    top = max(cves, key=lambda c: c["predicted_risk"])
    kev = sum(c["kev"] for c in cves)
    el = [Paragraph("취약점 분석 보고서", title),
          Paragraph(datetime.now().strftime("생성일 %Y-%m-%d %H:%M"), small),
          Spacer(1, 8),
          Paragraph(f"총 취약점 {len(cves)}건 · KEV 악용중 {kev}건 · "
                    f"최고위험 {top['cve_id']} ({severity(top['predicted_risk'])[0]})", body),
          Spacer(1, 10)]

    rows = [["순위", "CVE", "서비스", "CVSS", "EPSS", "위험도"]]
    for c in sorted(cves, key=lambda c: c["priority_rank"]):
        rows.append([str(c["priority_rank"]), c["cve_id"], f'{c["service"]} {c["version"]}',
                     str(c["cvss"]), f'{c["epss"]:.2f}', f'{c["predicted_risk"]:.2f}'])
    tbl = Table(rows, colWidths=[12 * mm, 34 * mm, 42 * mm, 16 * mm, 16 * mm, 18 * mm])
    tbl.setStyle(TableStyle([
        ("FONTNAME", (0, 0), (-1, -1), KRFONT), ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1e293b")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#cbd5e1")),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f1f5f9")]),
    ]))
    el += [tbl, Spacer(1, 14), Paragraph("취약점 상세 및 대응 방안", head)]
    for c in sorted(cves, key=lambda c: c["priority_rank"]):
        el += [Spacer(1, 6),
               Paragraph(f'<b>{c["cve_id"]}</b> · {c["service"]} {c["version"]} '
                         f'· {severity(c["predicted_risk"])[0]}', body),
               Paragraph(c["description"], small),
               Paragraph(f'대응: {generate_fix_with_ai(c)}', small)]
    doc.build(el)
    return buf.getvalue()


# ── 차트 ───────────────────────────────────────────────────────────────
def _dark(fig, title):
    fig.update_layout(title=title, height=260, template="plotly_dark",
                      margin=dict(l=10, r=20, t=40, b=10), font_color="#e2e8f0",
                      paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)")
    return fig


def severity_donut(cves):
    counts = {"High": 0, "Medium": 0, "Low": 0}
    for c in cves:
        counts[severity(c["predicted_risk"])[0]] += 1
    fig = go.Figure(go.Pie(labels=list(counts), values=list(counts.values()), hole=0.62,
                           marker_colors=[RISK_RED, RISK_AMBER, RISK_GRAY], sort=False))
    return _dark(fig, "위험도 분포")


def port_distribution(cves):
    counter = Counter(f'{c["port"]} · {c["service"]}' for c in cves)
    items = sorted(counter.items(), key=lambda kv: kv[1])
    fig = go.Figure(go.Bar(x=[v for _, v in items], y=[k for k, _ in items], orientation="h",
                           marker_color="#38bdf8", text=[v for _, v in items], textposition="outside"))
    fig = _dark(fig, "포트 상태 분포")
    fig.update_xaxes(title="취약점 수", dtick=1)
    return fig


@st.dialog("분석 결과 대시보드", width="large")
def show_dashboard(cves):
    st.download_button("📄 PDF 보고서 다운로드", data=build_pdf_report(cves),
                       file_name="취약점_분석_보고서.pdf", mime="application/pdf",
                       use_container_width=True)
    st.write("")

    ports = len({c["port"] for c in cves})
    services = len({c["service"] for c in cves})
    max_risk = severity(max(c["predicted_risk"] for c in cves))[0] if cves else "-"
    m = st.columns(5)
    m[0].metric("스캔 대상", "1")
    m[1].metric("열린 포트", ports)
    m[2].metric("식별 서비스", services)
    m[3].metric("취약점 수", len(cves))
    m[4].metric("위험도(최대)", max_risk)
    g1, g2 = st.columns(2)
    g1.plotly_chart(severity_donut(cves), use_container_width=True)
    g2.plotly_chart(port_distribution(cves), use_container_width=True)
    st.markdown("###### AI 발견 취약점 상세 리포트")
    for c in sorted(cves, key=lambda c: c["priority_rank"]):
        label, _ = severity(c["predicted_risk"])
        kev = ' <span class="badge-kev">KEV 악용중</span>' if c["kev"] else ""
        with st.expander(f'{c["cve_id"]} · {c["service"]} {c["version"]} · {label}'):
            st.markdown(f'CVSS {c["cvss"]} · EPSS {c["epss"]:.2f}{kev}', unsafe_allow_html=True)
            st.write(c["description"])
            st.markdown(f'<div class="fix-box">🛠 <b>대응 방안:</b> {generate_fix_with_ai(c)}</div>',
                        unsafe_allow_html=True)


# ── 세션 ───────────────────────────────────────────────────────────────
if "messages" not in st.session_state:
    st.session_state.messages = [
        {"role": "assistant", "text": "스캐닝 대상을 지정하거나 Nmap 스캔 결과를 직접 붙여넣어 분석을 시작하세요."}]
if "cves" not in st.session_state:
    st.session_state.cves = None


def render_chat_panel():
    rows = ['<div class="chatpanel">',
            '<div class="chathead"><span>☰</span><span>⋮</span></div>']
    for msg in st.session_state.messages:
        text = html.escape(msg["text"]).replace("\n", "<br>")
        if msg["role"] == "user":
            rows.append(f'<div class="bubble user">{text}</div>')
        else:
            rows.append(f'<div class="bubble bot"><span class="ic">◈ AI</span>  {text}</div>')
    rows.append("</div>")
    st.markdown("\n".join(rows), unsafe_allow_html=True)


# ── 헤더 ───────────────────────────────────────────────────────────────
st.title("🛡️ AI 침투 테스트 지원 시스템")
st.markdown('<div class="soc-sub">SECURITY OPERATIONS · VULNERABILITY ANALYSIS</div>',
            unsafe_allow_html=True)
st.write("")

left, right = st.columns([1.5, 1])

with left:
    st.markdown('<div class="sec-label">챗봇 영역</div>', unsafe_allow_html=True)
    render_chat_panel()

    # 입력 방식 선택형 탭 레이아웃 (수동 텍스트 입력 vs Live Nmap 스캔 연동)
    tab1, tab2 = st.tabs(["⚡ Live Nmap Scanner 연동", "✍ Nmap 텍스트 직접 입력"])

    with tab1:
        col_t1, col_t2 = st.columns([2, 1])
        target_input = col_t1.text_input("스캔 대상 호스트", value="127.0.0.1", placeholder="IP 주소 또는 도메인")
        scan_options = col_t2.text_input("Nmap 옵션", value="-sV -F", placeholder="예: -sV -p 22,80")
        start_live_scan = st.button("🚀 Nmap 라이브 스캔 가동", type="primary", use_container_width=True)

    with tab2:
        scan_text = st.text_area("스캔 결과 직접 입력", height=90, label_visibility="collapsed",
                                 placeholder="여기에 복사한 Nmap 실행 결과를 직접 붙여넣으세요...")
        start_manual_scan = st.button("Nmap 결과 텍스트 업로드 및 분석 시작", use_container_width=True)

    followup = st.chat_input("분석된 취약점에 대해 질문하세요")

with right:
    st.markdown('<div class="sec-label">분석 상태 및 제어</div>', unsafe_allow_html=True)
    done = st.session_state.cves is not None
    st.progress(100 if done else 0, text="파싱·분석 완료" if done else "대기 중")

    st.markdown("팝업 제어")
    auto_open = st.toggle("대시보드 팝업 자동 열기", value=True)
    if st.button("새 창으로 분석 결과 보기", use_container_width=True, disabled=not done):
        show_dashboard(st.session_state.cves)

    st.markdown("AI Context · parsed entities")
    if done:
        cves = st.session_state.cves
        top = max(cves, key=lambda c: c["predicted_risk"])
        cards = [
            ("🔌", f'포트 {len({c["port"] for c in cves})}개', "스캔 탐지"),
            ("📦", f'{top["service"]} {top["version"]}', f'{severity(top["predicted_risk"])[0]}'),
            ("🗂️", f'자산 {len(cves)}건', "취약점 식별"),
        ]
        for icon, title, sub in cards:
            st.markdown(f'<div class="ecard"><span>{icon}</span>'
                        f'<span>{title} <small>· {sub}</small></span></div>',
                        unsafe_allow_html=True)
    else:
        st.caption("분석 시작 후 파싱된 엔티티가 표시됩니다.")


# ── 입력 처리 및 Nmap 대기 제어 ──────────────────────────────────────────
def run_analysis(user_text):
    st.session_state.messages.append({"role": "user", "text": user_text})
    st.session_state.cves = analyze_scan(user_text)
    cves = st.session_state.cves
    top = max(cves, key=lambda c: c["predicted_risk"])
    st.session_state.messages.append({"role": "assistant", "text":
                                      f"분석 완료 — 취약점 {len(cves)}건 탐지. 최고위험 {top['cve_id']} "
                                      f"({severity(top['predicted_risk'])[0]}). 우측/팝업에서 상세 확인."})
    st.session_state.pending_dialog = True


# 1) Live Nmap 실시간 스캔 가동 처리
if start_live_scan:
    # 스캔 동작 도중 대기 화면 출력 및 비동기 처리 시뮬레이션
    with st.spinner(f"🔍 '{target_input}'을(를) 대상으로 Nmap 스캔 수행 중... 결과 대기 중..."):
        raw_output = run_live_scan(target_input, scan_options)
    run_analysis(raw_output)
    st.rerun()

# 2) 수동 텍스트 입력 처리
if start_manual_scan:
    run_analysis(scan_text.strip() or "80/tcp Apache 2.4.49\n22/tcp OpenSSH 7.4")
    st.rerun()

# 3) 추가 대화 처리
if followup:
    if st.session_state.cves is None:
        run_analysis(followup)
    else:
        st.session_state.messages.append({"role": "user", "text": followup})
        hit = next((c for c in st.session_state.cves
                    if c["cve_id"].lower() in followup.lower()), None)
        ans = (f'{hit["cve_id"]} — {hit["description"]} 🛠 {generate_fix_with_ai(hit)}'
               if hit else "분석된 CVE 번호를 넣어 질문하면 상세 설명을 드릴게요.")
        st.session_state.messages.append({"role": "assistant", "text": ans})
    st.rerun()

if st.session_state.pop("pending_dialog", False) and auto_open:
    show_dashboard(st.session_state.cves)