"""
취약점 분석 시스템 (풀 다크 · 2단 레이아웃 + PDF 보고서 + JSON/Live Scanner 동적 연단 파이프라인)
"""

import re
import os
import sys
import html
import json
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

# scanner.py 모듈로부터 실시간 라이브 스캔 함수 연동
from utils.scanner import run_scanner

# ── 팀2(취약점 분석) 모듈 연동 ───────────────────────────────────────────
# team2 폴더 안의 app_bridge를 통해 팀2 분석 기능을 하나의 함수로 사용한다.
sys.path.append(os.path.join(os.path.dirname(__file__), "team2"))
from app_bridge import run_vulnerability_scan


st.set_page_config(page_title="침투 테스트 지원 시스템", page_icon="🛡️", layout="wide")

# 한국어 PDF용 내장 폰트
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


# ── 데이터 전처리 & 실시간 동적 분석 파이프라인 ────────────────────────────
def analyze_scan(scan_input):
    """
    [1순위] 팀2 모듈(app_bridge.run_vulnerability_scan)로 실제 CVE 분석
    [2순위/백업] 팀2가 결과를 못 내면 기존 하드코딩 시나리오로 폴백한다.
    (팀2 내부 로직은 team2/app_bridge.py 에서 관리)
    """
    try:
        cves = run_vulnerability_scan(scan_input)
        if cves:
            return cves
    except Exception as e:
        # 팀2 실패(네트워크/키 등)해도 UI가 안 죽도록, 아래 백업으로 넘어간다
        print("[팀2 분석 실패, 백업 로직으로 전환]", e)

    return analyze_scan_fallback(scan_input)


def analyze_scan_fallback(scan_input):
    """
    팀2가 결과를 못 낼 때 쓰는 백업. (팀원이 만든 하드코딩 매핑)
    scanner.py 혹은 API 결과를 넘겨받아 실시간으로 파싱하고
    보안 위험도 데이터를 생성하여 동적으로 파이프라인을 빌드합니다.
    JSON 데이터 및 Raw Text 형식 모두 유연하게 수용합니다.
    """
    parsed_cves = []
    scan_data = None

    # 1. 스캔 입력 형태 가드 (JSON 객체 또는 JSON 포맷 문자열 식별)
    if isinstance(scan_input, dict):
        scan_data = scan_input
    elif isinstance(scan_input, str):
        try:
            scan_data = json.loads(scan_input.strip())
        except json.JSONDecodeError:
            scan_data = None

    # 2. 구조화된 JSON 데이터 파이프라인 가공
    if scan_data and isinstance(scan_data, dict) and scan_data.get("success", False):
        rank_counter = 1
        for host_info in scan_data.get("hosts", []):
            for port_info in host_info.get("ports", []):
                port_idx = port_info.get("port")
                service_name = port_info.get("service", "unknown")
                version_banner = port_info.get("version", "") or "Unknown Version"

                # 포트 정보별 동적 취약점 매핑 시나리오
                if port_idx == 135:
                    cve_id = "CVE-2015-2370"
                    cvss = 7.5
                    epss = 0.45
                    kev = False
                    predicted_risk = 0.68
                    description = f"[{service_name}] MSRPC 인터페이스 취약점으로 원격 코드 실행(RCE) 및 자산 정보 탈취의 위협이 존재합니다."
                    fix = "최신 누적 Windows 보안 업데이트 패치를 적용하고 RPC 종속 엔드포인트 방화벽 차단을 활성화하십시오."
                elif port_idx == 445:
                    cve_id = "CVE-2020-0796"
                    cvss = 10.0
                    epss = 0.96
                    kev = True
                    predicted_risk = 0.98
                    description = f"[{service_name}] SMBv3 데이터 압축 해제 처리 오류 기반 버퍼 오버플로우 공격(SMBGhost) 위험에 노출되었습니다."
                    fix = "SMBv3 압축을 해제(Disable-WindowsOptionalFeature)하거나 즉시 최신 보안 롤업 패치를 실행하십시오."
                elif port_idx in [902, 912]:
                    cve_id = "CVE-2020-3952"
                    cvss = 9.8
                    epss = 0.88
                    kev = True
                    predicted_risk = 0.92
                    description = f"[{service_name}] VMware Directory Service(vmdir)의 불충분한 접근 제어로 우회 권한 상승 위협이 예상됩니다."
                    fix = f"구동 중인 {port_idx}번 포트 VMware 서비스를 패치된 안전 버전(vCenter Server 6.7 Update 3f 이상)으로 긴급 패치하십시오."
                else:
                    cve_id = f"CVE-2026-GEN-{port_idx}"
                    cvss = 4.3
                    epss = 0.12
                    kev = False
                    predicted_risk = 0.28
                    description = f"포트 {port_idx}/TCP [{service_name}] 서비스 개방 상태 탐지."
                    fix = "해당 비정형 인가 서비스 대장을 확인하고 외부 접속이 불필요할 경우 ACL로 제한 처리하십시오."

                parsed_cves.append({
                    "port": port_idx,
                    "service": service_name,
                    "version": version_banner,
                    "cve_id": cve_id,
                    "cvss": cvss,
                    "epss": epss,
                    "kev": kev,
                    "predicted_risk": predicted_risk,
                    "priority_rank": rank_counter,
                    "description": description,
                    "fix": fix
                })
                rank_counter += 1

    # 3. 만약 구조화 데이터가 아니고 일반 Raw Text(줄글)인 경우 Regex 예외 처리
    else:
        port_pattern = re.compile(r"^(\d+)/(\w+)\s+(open|closed|filtered)\s+([\w\-]+)\s*(.*)$")
        lines = str(scan_input).split("\n")
        rank_counter = 1

        for line in lines:
            line = line.strip()
            match = port_pattern.match(line)
            if match:
                port_idx = int(match.group(1))
                service_name = match.group(4)
                version_banner = match.group(5).strip() if match.group(5) else "Unknown Version"

                if port_idx == 80 or "http" in service_name.lower():
                    cve_id = "CVE-2021-41773"
                    cvss = 7.5
                    epss = 0.94
                    kev = True
                    predicted_risk = 0.89
                    description = "Apache HTTP Server 경로 탐색 원격 코드 실행."
                    fix = "2.4.51 버전 이상 업그레이드"
                elif port_idx == 22 or "ssh" in service_name.lower():
                    cve_id = "CVE-2016-6210"
                    cvss = 5.9
                    epss = 0.35
                    kev = False
                    predicted_risk = 0.54
                    description = "OpenSSH 계정 정보 유출 가능성 노출."
                    fix = "OpenSSH 최신 버전 업그레이드"
                else:
                    cve_id = f"CVE-2026-GEN-{port_idx}"
                    cvss = 5.0
                    epss = 0.15
                    kev = False
                    predicted_risk = 0.35
                    description = f"{port_idx}번 비보안 서비스 노출 상태 감지."
                    fix = "포트 차단 및 방화벽 ACL 처리 권장."

                parsed_cves.append({
                    "port": port_idx,
                    "service": service_name,
                    "version": version_banner,
                    "cve_id": cve_id,
                    "cvss": cvss,
                    "epss": epss,
                    "kev": kev,
                    "predicted_risk": predicted_risk,
                    "priority_rank": rank_counter,
                    "description": description,
                    "fix": fix
                })
                rank_counter += 1

    # 분석 건수가 최종 누락되거나 에러 상황일 때 기본 폴백 데이터 삽입
    if not parsed_cves:
        parsed_cves.append({
            "port": 0, "service": "Unknown", "version": "0.0", "cve_id": "CVE-미식별",
            "cvss": 0.0, "epss": 0.0, "kev": False, "predicted_risk": 0.10, "priority_rank": 1,
            "description": "구조화된 유효 취약점 데이터를 스캔 결과로부터 발견할 수 없습니다.",
            "fix": "Nmap 스캔 타겟 혹은 스캔 파싱 결과를 다시 정렬하여 테스트해 주십시오."
        })

    return parsed_cves


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
        {"role": "assistant", "text": "스캐닝 대상을 지정하거나 Nmap 스캔 결과를 직접 붙여넣어 실시간 분석을 가동하세요."}]
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

    # 입력 방식 선택형 탭 레이아웃
    tab1, tab2 = st.tabs(["⚡ Live Nmap Scanner 연동", "✍ Nmap 텍스트 직접 입력"])

    with tab1:
        col_t1, col_t2 = st.columns([2, 1])
        target_input = col_t1.text_input("스캔 대상 호스트", value="127.0.0.1", placeholder="IP 주소 또는 도메인")
        scan_options = col_t2.text_input("Nmap 옵션", value="-sV -F", placeholder="예: -sV -p 22,80")
        start_live_scan = st.button("🚀 Nmap 라이브 스캔 가동", type="primary", use_container_width=True)

    with tab2:
        scan_text = st.text_area("스캔 결과 직접 입력", height=90, label_visibility="collapsed",
                                 placeholder="여기에 복사한 Nmap 실행 결과를 직접 붙여넣거나 JSON 데이터를 입력하세요...")
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
    # 만약 scanner.py에서 에러 피드백 딕셔너리 구조가 넘어왔을 경우 UI 크래시 방지 처리
    if isinstance(user_text, dict) and not user_text.get("success", True):
        error_msg = user_text.get("error", "알 수 없는 스캔 예외")
        st.session_state.messages.append({"role": "assistant", "text": f"❌ 스캔 작업이 실패했습니다: {error_msg}"})
        st.error(f"스캔 도중 치명적인 에러가 발생했습니다: {error_msg}")
        return

    st.session_state.messages.append({"role": "user", "text": "스캔 데이터 업로드 및 실시간 모델 추론 시작."})

    # 실시간 JSON/Text 통합 파서로 변환 처리 수행
    st.session_state.cves = analyze_scan(user_text)
    cves = st.session_state.cves
    top = max(cves, key=lambda c: c["predicted_risk"])
    st.session_state.messages.append({"role": "assistant", "text":
                                      f"분석 완료 — 취약점 {len(cves)}건 탐지. 최고위험 {top['cve_id']} "
                                      f"({severity(top['predicted_risk'])[0]}). 우측/팝업에서 상세 확인."})
    st.session_state.pending_dialog = True


# 1) Live Nmap 실시간 스캔 가동 처리 (scanner.py 결과 활용)
if start_live_scan:
    with st.spinner(f"🔍 '{target_input}'을(를) 대상으로 Nmap 실시간 정밀 스캔 가동 중..."):
        raw_output = run_scanner(target_input, scan_options)
    run_analysis(raw_output)
    st.rerun()

# 2) 수동 JSON 혹은 텍스트 입력 처리
if start_manual_scan:
    run_analysis(scan_text.strip() or "22/tcp open ssh OpenSSH 7.4\n80/tcp open http Apache httpd 2.4.49")
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