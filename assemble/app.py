"""
취약점 분석 시스템 (풀 다크 · 2단 레이아웃 + PDF 보고서 + JSON/Live Scanner 동적 연단 파이프라인)
"""

import re
import sys
import html
import json
import os
from io import BytesIO
from pathlib import Path
from datetime import datetime
from collections import Counter

import streamlit as st
import plotly.graph_objects as go
from openai import OpenAI
from priority_predictor import PriorityPredictor

from reportlab.lib.pagesizes import A4
from reportlab.lib.units import mm
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    Image, PageBreak, KeepTogether,
)
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.cidfonts import UnicodeCIDFont

# scanner.py 모듈로부터 실시간 라이브 스캔 함수 연동
from utils.scanner import run_scanner

# ── 팀1 → 팀2 → 팀3 모듈 연동 ───────────────────────────────────────────
# 팀1: utils/scanner.py의 run_scanner()
# 팀2: app_bridge.py의 run_vulnerability_scan()
# 팀3: priority_predictor.py의 PriorityPredictor
#
# 팀2 작업물이 다음 구조 중 어디에 있어도 찾을 수 있도록 경로를 등록한다.
# 1) 프로젝트 루트/app_bridge.py
# 2) 프로젝트 루트/team2/app_bridge.py
# 3) app_bridge 없이 team2/vulnerability_service.py만 있는 구조
BASE_DIR = Path(__file__).resolve().parent
TEAM2_DIR = BASE_DIR / "team2"

for module_path in (BASE_DIR, TEAM2_DIR):
    module_path_str = str(module_path)
    if module_path.exists() and module_path_str not in sys.path:
        sys.path.insert(0, module_path_str)

TEAM2_BRIDGE_MODE = ""

if (BASE_DIR / "app_bridge.py").exists():
    # 현재 확인된 구조: app.py와 app_bridge.py가 같은 폴더
    from app_bridge import run_vulnerability_scan
    TEAM2_BRIDGE_MODE = "root_app_bridge"

elif (TEAM2_DIR / "app_bridge.py").exists():
    # team2 폴더 안에 app_bridge.py가 있는 구조
    from app_bridge import run_vulnerability_scan
    TEAM2_BRIDGE_MODE = "team2_app_bridge"

else:
    # app_bridge가 없는 경우 기존 팀2 analyze_services 방식으로 연결
    from vulnerability_service import analyze_services

    def run_vulnerability_scan(team1_result):
        services = extract_services(team1_result)

        if not services:
            raise ValueError(
                "팀1 결과에서 팀2 분석용 서비스 정보를 찾지 못했습니다."
            )

        return analyze_services(services)

    TEAM2_BRIDGE_MODE = "analyze_services_fallback"

# .env(OPENAI_API_KEY 등)를 읽어온다. 웹서치 기능에 필요
from dotenv import load_dotenv
load_dotenv(Path(__file__).parent / ".env", override=True)

OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "").strip()
OPENAI_MODEL = os.getenv("OPENAI_MODEL", "gpt-4.1-mini").strip()


st.set_page_config(page_title="침투 테스트 지원 시스템", page_icon="🛡️", layout="wide")


@st.cache_resource(show_spinner=False)
def get_priority_predictor() -> PriorityPredictor:
    """Random Forest 모델을 한 번만 불러온다."""
    return PriorityPredictor()


def predict_team2_results(
    team2_records: list[dict],
) -> list[dict]:
    """팀2 team3_records를 팀3 Random Forest 모델로 예측한다."""
    if not team2_records:
        raise ValueError(
            "팀2 분석 결과에 team3_records가 없습니다."
        )

    predictor = get_priority_predictor()
    return predictor.predict(team2_records)

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
[data-testid="stMetric"] {
background:#ffffff; border:1px solid #d1d5db; border-radius:10px; padding:14px;
}
[data-testid="stMetric"] * { color:#111827 !important; }
.badge-kev { background:#3d1418; color:#fca5a5; padding:1px 8px; border-radius:20px; font-size:12px; }
.fix-box { background:#0d2438; border-left:3px solid #38bdf8; border-radius:0 6px 6px 0;
padding:10px 12px; color:#bae6fd; font-size:14px; line-height:1.55; margin-top:6px; }
</style>
""", unsafe_allow_html=True)


def get_temporary_priority_score(
    record: dict,
) -> float:
    """
    실제 priority_score가 없거나 0이면
    CVSS × 10을 임시 Priority Score로 사용한다.
    """
    try:
        actual_score = float(
            record.get("priority_score") or 0
        )
    except (TypeError, ValueError):
        actual_score = 0.0

    if actual_score > 0:
        return round(actual_score, 2)

    try:
        cvss_score = float(
            record.get("cvss_score")
            or record.get("cvss")
            or 0
        )
    except (TypeError, ValueError):
        cvss_score = 0.0

    return round(
        max(0.0, min(cvss_score, 10.0)) * 10,
        2,
    )


# ── 팀2 결과 → app.py 화면 형식 변환 ────────────────────────────────────
def convert_team3_to_dashboard(
    priority_records: list[dict],
    team2_result: dict,
) -> list[dict]:
    """
    팀3 Random Forest 예측 결과를 app.py 화면 형식으로 변환한다.
    priority_score가 높은 순서대로 우선순위를 부여한다.
    """

    # 팀2 웹 검색 결과를 CVE별로 저장
    # app_bridge가 dict 또는 list를 반환해도 화면 변환이 중단되지 않도록 처리한다.
    web_by_cve = {}

    if isinstance(team2_result, dict):
        for service_result in team2_result.get("services", []):
            if not isinstance(service_result, dict):
                continue

            for vulnerability in service_result.get("vulnerabilities", []):
                if not isinstance(vulnerability, dict):
                    continue

                cve_id = vulnerability.get("cve_id")
                web_result = vulnerability.get("web")

                if cve_id and web_result:
                    web_by_cve[cve_id] = web_result

    cves = []

    for record in priority_records:
        cve_id = record.get("cve_id")
        cvss_score = float(
            record.get("cvss_score") or 0
        )
        original_priority_score = record.get(
            "priority_score"
        )

        priority_score = get_temporary_priority_score(
            record
        )

        is_temporary_score = not (
            original_priority_score not in (None, "", 0, 0.0)
            and float(original_priority_score) > 0
        )

        web_result = web_by_cve.get(cve_id)

        if web_result and not web_result.get("error"):
            summary = web_result.get("summary") or ""
            mitigation = web_result.get("mitigation") or []

            if mitigation:
                fix_text = "  •  ".join(mitigation)
            elif summary:
                fix_text = summary
            else:
                fix_text = "웹 검색 결과 없음"

            description = (
                summary
                or record.get("description", "")
            )
        else:
            description = record.get(
                "description",
                "",
            )
            fix_text = (
                "팀2 웹 검색이 실행되지 않았거나 "
                "대응 방안을 불러오지 못했습니다."
            )

        cves.append(
            {
                "port": record.get("port"),
                "service": (
                    record.get("product")
                    or record.get("service")
                    or ""
                ),
                "version": record.get("version") or "",
                "cve_id": cve_id,
                "cvss": cvss_score,
                "epss": 0.0,
                "kev": False,

                # 앱 화면은 0~1 값을 사용하므로 100점 기준을 변환
                "predicted_risk": round(
                    priority_score / 100,
                    3,
                ),

                # 팀3 핵심 결과
                "priority_score": priority_score,
                "priority_score_is_temporary": is_temporary_score,
                "priority_rank": 0,
                "predicted_severity": record.get(
                    "predicted_severity"
                ),
                "response_priority": record.get(
                    "response_priority"
                ),

                "description": description,
                "fix": fix_text,
                "cwe": record.get("cwe"),
                "attack_vector": record.get(
                    "attack_vector"
                ),
                "attack_complexity": record.get(
                    "attack_complexity"
                ),
                "privileges_required": record.get(
                    "privileges_required"
                ),
                "user_interaction": record.get(
                    "user_interaction"
                ),
            }
        )

    # 팀3 priority_score가 높은 순서대로 정렬
    cves.sort(
        key=lambda item: (
            float(item.get("priority_score") or 0),
            float(item.get("cvss") or 0),
        ),
        reverse=True,
    )

    # 최종 순위 부여
    for rank, cve in enumerate(cves, start=1):
        cve["priority_rank"] = rank

    return cves


# ── nmap 입력 → 팀2 서비스 형식 변환 ─────────────────────────────────────
def extract_services(scan_input):
    """
    scan_input(JSON dict/문자열 또는 raw text)에서 포트/서비스/버전을 뽑아
    팀2 analyze_services가 받는 형식으로 변환한다.
    """
    services = []

    # 입력이 JSON(dict 또는 JSON 문자열)인지 확인
    scan_data = None
    if isinstance(scan_input, dict):
        scan_data = scan_input
    elif isinstance(scan_input, str):
        try:
            scan_data = json.loads(scan_input.strip())
        except json.JSONDecodeError:
            scan_data = None

    # (A) 구조화된 JSON (팀1 scanner/parser 결과)
    if scan_data and isinstance(scan_data, dict) and scan_data.get("success", False):
        for host_info in scan_data.get("hosts", []):
            host_ip = host_info.get("ip")
            for p in host_info.get("ports", []):
                if p.get("state") not in (None, "open"):
                    continue
                services.append({
                    "host": host_ip,
                    "port": int(p.get("port", 0)),
                    "protocol": p.get("protocol", "TCP"),
                    "status": "open",
                    "service": p.get("service", ""),
                    "product": p.get("product") or None,
                    "version": p.get("version") or None,
                    "vendor": None,
                    "extra_info": p.get("extrainfo") or None,
                })
        return services

    # (B) raw text (사용자가 붙여넣은 nmap 결과)
    for line in str(scan_input).splitlines():
        m = re.match(r"\s*(\d+)/(tcp|udp)\s+open\s+(\S+)\s*(.*)", line, re.IGNORECASE)
        if not m:
            continue
        port, proto, service, rest = m.groups()
        product, version = None, None
        if rest.strip():
            parts = rest.strip().rsplit(" ", 1)
            if len(parts) == 2 and any(ch.isdigit() for ch in parts[1]):
                product, version = parts[0], parts[1]
            else:
                product = rest.strip()
        services.append({
            "host": None,
            "port": int(port),
            "protocol": proto.upper(),
            "status": "open",
            "service": service,
            "product": product,
            "version": version,
            "vendor": None,
            "extra_info": None,
        })
    return services



def extract_team3_records(
    team2_result,
) -> list[dict]:
    """
    준엽님 팀2 app_bridge 반환값을 팀3 모델 입력용 list[dict]로 정규화한다.

    지원 형식:
    1. {"team3_records": [...]}
    2. {"services": [{"vulnerabilities": [...]}]}
    3. {"result": ...}, {"data": ...}, {"output": ...}
    4. 취약점 dict의 list
    """

    def normalize_record(
        item: dict,
        defaults: dict | None = None,
    ) -> dict | None:
        if not isinstance(item, dict):
            return None

        defaults = defaults or {}
        source = item.get("nvd") if isinstance(item.get("nvd"), dict) else item

        cve_id = (
            item.get("cve_id")
            or item.get("id")
            or source.get("cve_id")
            or source.get("id")
        )
        if not cve_id:
            return None

        return {
            "host": item.get("host") or defaults.get("host"),
            "port": item.get("port") or defaults.get("port"),
            "service": (
                item.get("service")
                or defaults.get("service")
                or item.get("product")
                or "UNKNOWN"
            ),
            "product": item.get("product") or defaults.get("product"),
            "version": (
                item.get("version")
                or defaults.get("version")
                or "UNKNOWN"
            ),
            "cve_id": str(cve_id).upper(),
            "cwe": item.get("cwe") or source.get("cwe") or "UNKNOWN",
            "cvss_score": (
                item.get("cvss_score")
                or item.get("cvss")
                or item.get("base_score")
                or source.get("cvss_score")
                or source.get("cvss")
                or source.get("base_score")
                or 0.0
            ),
            "severity": (
                item.get("severity")
                or item.get("predicted_severity")
                or source.get("severity")
                or "UNKNOWN"
            ),
            "attack_vector": (
                item.get("attack_vector")
                or source.get("attack_vector")
                or "UNKNOWN"
            ),
            "attack_complexity": (
                item.get("attack_complexity")
                or source.get("attack_complexity")
                or "UNKNOWN"
            ),
            "privileges_required": (
                item.get("privileges_required")
                or source.get("privileges_required")
                or "UNKNOWN"
            ),
            "user_interaction": (
                item.get("user_interaction")
                or source.get("user_interaction")
                or "UNKNOWN"
            ),
            "description": (
                item.get("description")
                or source.get("description")
                or ""
            ),
        }

    if isinstance(team2_result, dict):
        for wrapper_key in ("result", "data", "output"):
            wrapped = team2_result.get(wrapper_key)
            if isinstance(wrapped, (dict, list)):
                nested_records = extract_team3_records(wrapped)
                if nested_records:
                    return nested_records

    if isinstance(team2_result, list):
        records = []
        for item in team2_result:
            normalized = normalize_record(item)
            if normalized:
                records.append(normalized)
        return records

    if not isinstance(team2_result, dict):
        return []

    direct_records = team2_result.get("team3_records", [])
    if isinstance(direct_records, list) and direct_records:
        records = []
        for item in direct_records:
            normalized = normalize_record(item)
            if normalized:
                records.append(normalized)
        return records

    records: list[dict] = []

    for service_result in team2_result.get("services", []):
        if not isinstance(service_result, dict):
            continue

        defaults = {
            "host": service_result.get("host"),
            "port": service_result.get("port"),
            "service": service_result.get("service"),
            "product": service_result.get("product"),
            "version": service_result.get("version"),
        }

        vulnerabilities = (
            service_result.get("vulnerabilities")
            or service_result.get("cves")
            or service_result.get("results")
            or []
        )

        if not isinstance(vulnerabilities, list):
            continue

        for vulnerability in vulnerabilities:
            normalized = normalize_record(vulnerability, defaults)
            if normalized:
                records.append(normalized)

    return records


# ── 데이터 전처리 & 실시간 동적 분석 파이프라인 ────────────────────────────
def analyze_scan(scan_input):
    """
    Nmap 결과
    → 팀2 취약점 분석
    → 팀2 결과 형식 자동 정규화
    → 팀3 Random Forest 예측
    → 우선순위 정렬
    → 대시보드 및 AI 챗봇 세션 저장
    """
    try:
        # 팀1 결과를 팀2 브리지에 그대로 전달한다.
        # Live Scanner에서는 run_scanner() 반환 dict,
        # 수동 입력에서는 Nmap 텍스트 또는 JSON 문자열이 들어온다.
        team1_result = scan_input

        # 팀1 → 팀2 공식 연결 지점
        team2_result = run_vulnerability_scan(
            team1_result
        )

        if not team2_result:
            raise ValueError(
                "팀2 run_vulnerability_scan() 결과가 비어 있습니다."
            )

        # team3_records 직접 반환 / services 내부 취약점 모두 대응
        team2_records = extract_team3_records(
            team2_result
        )

        if not team2_records:
            raise ValueError(
                "팀2 결과에서 팀3 모델 입력용 CVE 데이터를 찾지 못했습니다."
            )

        # 팀3 Random Forest 실행
        priority_records = predict_team2_results(
            team2_records
        )

        if not priority_records:
            raise ValueError(
                "팀3 Random Forest 예측 결과가 비어 있습니다."
            )

        # 원본 팀3 결과를 챗봇에서 사용할 수 있도록 저장
        st.session_state.risk_records = priority_records
        st.session_state.risk_source = (
            "실시간 스캔 및 팀3 ML 분석 결과"
        )
        st.session_state.team2_result = team2_result
        st.session_state.team2_bridge_mode = TEAM2_BRIDGE_MODE

        # 대시보드 형식으로 변환
        cves = convert_team3_to_dashboard(
            priority_records,
            team2_result,
        )

        if not cves:
            raise ValueError(
                "팀3 결과를 대시보드 형식으로 변환하지 못했습니다."
            )

        return cves

    except Exception as error:
        st.warning(
            "팀2 → 팀3 연동 또는 Random Forest 예측에 실패해 "
            "CVSS 기반 백업 결과를 사용합니다. "
            f"원인: {error}"
        )

        fallback_cves = analyze_scan_fallback(
            scan_input
        )

        for cve in fallback_cves:
            try:
                cvss_score = float(
                    cve.get("cvss") or 0
                )
            except (TypeError, ValueError):
                cvss_score = 0.0

            cve["priority_score"] = round(
                max(0.0, min(cvss_score, 10.0)) * 10,
                2,
            )
            cve["priority_score_is_temporary"] = True
            cve["response_priority"] = (
                " "
            )

        fallback_cves.sort(
            key=lambda item: (
                float(item.get("priority_score") or 0),
                float(item.get("cvss") or 0),
            ),
            reverse=True,
        )

        for rank, cve in enumerate(
            fallback_cves,
            start=1,
        ):
            cve["priority_rank"] = rank
            cve["predicted_risk"] = round(
                float(cve["priority_score"]) / 100,
                3,
            )

        st.session_state.risk_records = (
            fallback_cves
        )
        st.session_state.risk_source = (
            "CVSS 기반 임시 Priority Score"
        )

        return fallback_cves


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
def _pdf_severity_chart(cves):
    """PDF 전용 위험도 분포 차트: 흰 배경, 검은 글씨, 0건 항목 제외."""
    counts = {"High": 0, "Medium": 0, "Low": 0}
    for c in cves:
        counts[severity(c["predicted_risk"])[0]] += 1

    labels = [label for label, value in counts.items() if value > 0]
    values = [counts[label] for label in labels]
    color_map = {"High": RISK_RED, "Medium": RISK_AMBER, "Low": RISK_GRAY}

    fig = go.Figure(
        go.Pie(
            labels=labels,
            values=values,
            hole=0.58,
            sort=False,
            marker_colors=[color_map[label] for label in labels],
            textinfo="label+percent",
            textposition="auto",
            textfont=dict(color="#111827", size=20),
            insidetextfont=dict(color="#111827", size=20),
            outsidetextfont=dict(color="#111827", size=20),
            hoverinfo="skip",
        )
    )
    fig.update_layout(
        title=dict(
            text="위험도 분포",
            x=0.02,
            xanchor="left",
            font=dict(color="#111827", size=26),
        ),
        width=1200,
        height=560,
        margin=dict(l=50, r=70, t=90, b=40),
        paper_bgcolor="white",
        plot_bgcolor="white",
        font=dict(color="#111827", size=18),
        legend=dict(
            orientation="v",
            x=1.0,
            xanchor="right",
            y=0.9,
            font=dict(color="#111827", size=18),
            bgcolor="rgba(255,255,255,0)",
        ),
        uniformtext_minsize=16,
        uniformtext_mode="hide",
    )
    return fig


def _pdf_port_chart(cves):
    """PDF 전용 포트 분포 차트: 긴 라벨 정리 및 검은 축 글씨 적용."""
    counter = Counter(f'{c["port"]} · {c["service"]}' for c in cves)
    items = sorted(counter.items(), key=lambda kv: (kv[1], kv[0]))

    def shorten(label, limit=34):
        return label if len(label) <= limit else label[: limit - 1] + "…"

    labels = [shorten(label) for label, _ in items]
    values = [value for _, value in items]
    chart_height = max(560, 90 + len(items) * 65)

    fig = go.Figure(
        go.Bar(
            x=values,
            y=labels,
            orientation="h",
            marker_color="#38bdf8",
            text=values,
            textposition="outside",
            textfont=dict(color="#111827", size=19),
            cliponaxis=False,
            hoverinfo="skip",
        )
    )
    fig.update_layout(
        title=dict(
            text="포트별 취약점 분포",
            x=0.02,
            xanchor="left",
            font=dict(color="#111827", size=26),
        ),
        width=1200,
        height=chart_height,
        margin=dict(l=260, r=90, t=90, b=85),
        paper_bgcolor="white",
        plot_bgcolor="white",
        font=dict(color="#111827", size=18),
        bargap=0.25,
        showlegend=False,
    )
    fig.update_xaxes(
        title=dict(text="취약점 수", font=dict(color="#111827", size=19)),
        tickfont=dict(color="#111827", size=17),
        color="#111827",
        dtick=1,
        rangemode="tozero",
        gridcolor="#d1d5db",
        zerolinecolor="#6b7280",
        linecolor="#374151",
        showline=True,
    )
    fig.update_yaxes(
        tickfont=dict(color="#111827", size=17),
        color="#111827",
        gridcolor="#eef2f7",
        linecolor="#374151",
        showline=True,
        automargin=True,
    )
    return fig


def build_pdf_report(cves):
    buf = BytesIO()
    doc = SimpleDocTemplate(
        buf,
        pagesize=A4,
        topMargin=16 * mm,
        bottomMargin=16 * mm,
        leftMargin=16 * mm,
        rightMargin=16 * mm,
    )
    ss = getSampleStyleSheet()
    title = ParagraphStyle(
        "t", parent=ss["Title"], fontName=KRFONT, fontSize=18,
        leading=24, textColor=colors.HexColor("#111827"),
    )
    head = ParagraphStyle(
        "h", parent=ss["Heading2"], fontName=KRFONT, fontSize=13,
        leading=18, spaceAfter=6, textColor=colors.HexColor("#1e40af"),
    )
    body = ParagraphStyle(
        "b", parent=ss["Normal"], fontName=KRFONT, fontSize=10,
        leading=15, textColor=colors.HexColor("#111827"),
    )
    small = ParagraphStyle(
        "s", parent=body, fontSize=9, leading=14,
        textColor=colors.HexColor("#374151"),
    )

    top = max(cves, key=lambda c: c["predicted_risk"])
    kev = sum(bool(c.get("kev")) for c in cves)
    el = [
        Paragraph("취약점 분석 보고서", title),
        Paragraph(datetime.now().strftime("생성일 %Y-%m-%d %H:%M"), small),
        Spacer(1, 8),
        Paragraph(
            f"총 취약점 {len(cves)}건 · KEV 악용중 {kev}건 · "
            f"최고위험 {top['cve_id']} ({severity(top['predicted_risk'])[0]})",
            body,
        ),
        Spacer(1, 12),
        Paragraph("1. 시각화 결과", head),
    ]

    # 대시보드 차트와 별개로 PDF 전용 흰색 차트를 고해상도 PNG로 변환한다.
    severity_png = BytesIO(
        _pdf_severity_chart(cves).to_image(
            format="png", width=1200, height=560, scale=2,
        )
    )
    port_fig = _pdf_port_chart(cves)
    port_height = int(port_fig.layout.height or 560)
    port_png = BytesIO(
        port_fig.to_image(
            format="png", width=1200, height=port_height, scale=2,
        )
    )
    severity_png.seek(0)
    port_png.seek(0)

    # 원본 종횡비를 유지해 글씨와 그래프가 눌리지 않도록 한다.
    el += [
        Image(severity_png, width=176 * mm, height=82 * mm),
        Spacer(1, 5),
        Image(
            port_png,
            width=176 * mm,
            height=min(100 * mm, 176 * mm * port_height / 1200),
        ),
        PageBreak(),
        Paragraph("2. 취약점 우선순위", head),
    ]

    rows = [["순위", "CVE", "서비스", "CVSS", "우선점수", "위험도"]]
    for c in sorted(cves, key=lambda c: c["priority_rank"]):
        service_text = f'{c["service"]} {c["version"]}'.strip()
        rows.append([
            str(c["priority_rank"]),
            c["cve_id"],
            Paragraph(service_text, small),
            str(c["cvss"]),
            f'{c.get("priority_score", 0):.1f}',
            f'{c["predicted_risk"]:.2f}',
        ])

    tbl = Table(
        rows,
        colWidths=[12 * mm, 36 * mm, 55 * mm, 18 * mm, 22 * mm, 20 * mm],
        repeatRows=1,
        hAlign="LEFT",
    )
    tbl.setStyle(TableStyle([
        ("FONTNAME", (0, 0), (-1, -1), KRFONT),
        ("FONTSIZE", (0, 0), (-1, -1), 8.5),
        ("LEADING", (0, 0), (-1, -1), 12),
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1e293b")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("TEXTCOLOR", (0, 1), (-1, -1), colors.HexColor("#111827")),
        ("ALIGN", (0, 0), (1, -1), "CENTER"),
        ("ALIGN", (3, 0), (-1, -1), "CENTER"),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#cbd5e1")),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [
            colors.white,
            colors.HexColor("#f8fafc"),
        ]),
    ]))
    el += [tbl, PageBreak(), Paragraph("3. 취약점 상세 및 대응 방안", head)]

    for c in sorted(cves, key=lambda c: c["priority_rank"]):
        detail = KeepTogether([
            Spacer(1, 7),
            Paragraph(
                f'<b>{c["cve_id"]}</b> · {c["service"]} {c["version"]} '
                f'· {severity(c["predicted_risk"])[0]}',
                body,
            ),
            Paragraph(c["description"], small),
            Paragraph(f'대응: {generate_fix_with_ai(c)}', small),
            Spacer(1, 3),
        ])
        el.append(detail)

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
            temporary_label = (
                " "
                if c.get("priority_score_is_temporary")
                else ""
            )

            st.markdown(
                (
                    f'우선순위 {c["priority_rank"]}위 · '
                    f'CVSS {c["cvss"]} · '
                    f'{c.get("response_priority") or "분석 완료"}'
                    f'{kev}'
                ),
                unsafe_allow_html=True,
            )           

        
            st.write(c["description"])
            st.markdown(f'<div class="fix-box">🛠 <b>대응 방안:</b> {generate_fix_with_ai(c)}</div>',
                        unsafe_allow_html=True)


# ── 세션 ───────────────────────────────────────────────────────────────
if "messages" not in st.session_state:
    st.session_state.messages = [
        {"role": "assistant", "text": "스캐닝 대상을 지정하거나 Nmap 스캔 결과를 직접 붙여넣어 실시간 분석을 가동하세요."}]
if "cves" not in st.session_state:
    st.session_state.cves = None

if "risk_records" not in st.session_state:
    st.session_state.risk_records = []

if "risk_source" not in st.session_state:
    st.session_state.risk_source = "없음"

if "team2_result" not in st.session_state:
    st.session_state.team2_result = None

if "team2_bridge_mode" not in st.session_state:
    st.session_state.team2_bridge_mode = TEAM2_BRIDGE_MODE


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



# ── OpenAI 챗봇 연동 ────────────────────────────────────────────────────
CHAT_SYSTEM_PROMPT = """
당신은 '취약점 찾아조' 프로젝트의 AI 챗봇입니다.

역할:
- 보안 및 취약점 질문에는 현재 앱에서 실제로 분석한 결과를 우선 근거로 답변합니다.
- 일상 대화, 프로그래밍, 학습, 일반 상식 등 보안 외의 질문에도 자연스럽게 답변합니다.

보안 답변 원칙:
- 제공된 분석 결과에 없는 CVE, 점수, 우선순위를 만들어내지 않습니다.
- CVSS 점수와 분석 결과를 기준으로 위험도를 설명합니다.
- 상위 취약점, 1순위, 대응 방안, 특정 CVE 질문은 제공된 분석 결과를 기준으로 답합니다.
- 공격 수행 절차보다는 조치 우선순위, 패치, 완화 방안을 중심으로 답합니다.
- 보안 질문인데 분석 결과가 없다면 먼저 스캔 또는 Nmap 분석을 실행하라고 안내합니다.

일반 답변 원칙:
- 보안과 관계없는 질문은 현재 취약점 결과에 억지로 연결하지 않습니다.
- 사용자의 질문에 직접적이고 자연스럽게 한국어로 답변합니다.
"""



def get_openai_client():
    if not OPENAI_API_KEY:
        raise ValueError(
            ".env에서 OPENAI_API_KEY를 찾지 못했습니다."
        )
    return OpenAI(api_key=OPENAI_API_KEY)


def build_cve_context(cves, limit=50):
    """
    app.py가 생성한 취약점 분석 결과를
    OpenAI에 전달하기 좋은 짧은 JSON 문맥으로 변환한다.
    """
    if not cves:
        return "현재 분석된 취약점 결과가 없습니다."

    sorted_cves = sorted(
        cves,
        key=lambda item: (
            float(item.get("priority_score") or 0),
            float(item.get("predicted_risk") or 0),
            float(item.get("cvss") or 0),
        ),
        reverse=True,
    )[:limit]

    compact = []

    for index, cve in enumerate(sorted_cves, start=1):
        compact.append(
            {
                "rank": cve.get("priority_rank") or index,
                "cve_id": cve.get("cve_id"),
                "port": cve.get("port"),
                "service": cve.get("service"),
                "version": cve.get("version"),
                "cvss": cve.get("cvss"),
                "priority_score": cve.get("priority_score"),
                "priority_score_is_temporary": cve.get(
                    "priority_score_is_temporary",
                    False,
                ),
                "predicted_risk": cve.get("predicted_risk"),
                "predicted_severity": cve.get("predicted_severity"),
                "response_priority": cve.get("response_priority"),
                "description": cve.get("description"),
                "fix": cve.get("fix"),
            }
        )

    return json.dumps(
        compact,
        ensure_ascii=False,
        indent=2,
    )


def is_security_question(question: str) -> bool:
    """질문이 보안 또는 현재 분석 결과와 관련됐는지 판단한다."""
    security_keywords = [
        "취약점",
        "보안",
        "cve",
        "cvss",
        "위험도",
        "우선순위",
        "priority",
        "공격",
        "익스플로잇",
        "exploit",
        "패치",
        "완화",
        "포트",
        "nmap",
        "스캔",
        "서비스",
        "버전",
        "apache",
        "mysql",
        "ssh",
        "http",
        "방화벽",
        "권한",
        "cwe",
        "1순위",
        "상위",
        "대응",
    ]

    normalized = question.lower()
    return any(
        keyword in normalized
        for keyword in security_keywords
    )

def run_ai_chat(user_question):
    """
    일반 질문은 AI에 바로 전달하고,
    보안 질문은 현재 취약점 분석 결과를 문맥으로 함께 전달한다.
    """
    client = get_openai_client()
    security_question = is_security_question(
        user_question
    )

    input_messages = [
        {
            "role": "system",
            "content": CHAT_SYSTEM_PROMPT,
        }
    ]

    if security_question:
        cve_source = (
            st.session_state.get("cves")
            or st.session_state.get("risk_records")
            or []
        )

        cve_context = build_cve_context(
            cve_source,
        )

        input_messages.append(
            {
                "role": "system",
                "content": (
                    "다음은 현재 앱에서 실제로 분석한 취약점 결과입니다. "
                    "보안 관련 질문에만 이 데이터를 우선 근거로 사용하세요. "
                    "데이터에 없는 CVE나 점수는 만들지 마세요.\n\n"
                    + cve_context
                ),
            }
        )
# 최근 대화 기록 전달
    for message in st.session_state.messages[-10:]:
        role = message.get("role")
        content = message.get("text")

        if role in {"user", "assistant"} and content:
            input_messages.append(
                {
                    "role": role,
                    "content": content,
                }
            )

    input_messages.append(
        {
            "role": "user",
            "content": user_question,
        }
    )

    response = client.responses.create(
        model=OPENAI_MODEL,
        input=input_messages,
        tools=[{"type": "web_search"}],
        tool_choice="auto",
    )

    return (
        response.output_text
        or "AI 응답 내용이 없습니다."
    )


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


# 1) 팀1 Live Nmap 스캔 → 팀2 취약점 분석 → 팀3 Random Forest 예측
if start_live_scan:
    with st.spinner(f"🔍 '{target_input}'을(를) 대상으로 Nmap 실시간 정밀 스캔 가동 중..."):
        team1_result = run_scanner(
            target_input,
            scan_options,
        )

    # run_analysis 내부에서
    # team1_result → run_vulnerability_scan() → PriorityPredictor 순서로 처리
    run_analysis(team1_result)
    st.rerun()

# 2) 수동 JSON 혹은 텍스트 입력 처리
if start_manual_scan:
    run_analysis(scan_text.strip() or "22/tcp open ssh OpenSSH 7.4\n80/tcp open http Apache httpd 2.4.49")
    st.rerun()

# 3) 추가 대화 처리
if followup:
    st.session_state.messages.append(
        {
            "role": "user",
            "text": followup,
        }
    )

    security_question = is_security_question(
        followup
    )

    if (
        security_question
        and not st.session_state.get("cves")
        and not st.session_state.get("risk_records")
    ):
        answer = (
            "아직 분석된 취약점 결과가 없습니다. "
            "현재 스캔 결과에 관한 질문이라면 먼저 Live Nmap 스캔 또는 "
            "Nmap 텍스트 분석을 실행해주세요."
        )
    else:
        spinner_message = (
            "현재 취약점 분석 결과를 바탕으로 AI가 답변을 생성 중입니다..."
            if security_question
            else "답변을 생성 중입니다!"
        )

        try:
            with st.spinner(spinner_message):
                answer = run_ai_chat(
                    followup
                )

        except Exception as error:
            answer = (
                f"AI 챗봇 호출 오류: {error}"
            )

    st.session_state.messages.append(
        {
            "role": "assistant",
            "text": answer,
        }
    )

    st.rerun()


if st.session_state.pop("pending_dialog", False) and auto_open:
    show_dashboard(st.session_state.cves)
