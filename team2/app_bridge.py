"""
app.py <-> team2 취약점 분석 모듈을 연결하는 다리(bridge) 모듈.

app.py는 이 파일의 run_vulnerability_scan() 함수 하나만 호출하면 된다.
(팀1 데이터 변환, 팀2 분석 실행, 화면 표시용 변환까지 이 파일 안에서 처리)

사용 예 (app.py에서):
    sys.path.append(str(Path(__file__).parent / "team2"))
    from app_bridge import run_vulnerability_scan

    cves = run_vulnerability_scan(scan_input)
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import Any

# team2 폴더 자체를 sys.path에 넣어준다.
# (module/, vulnerability_service.py 안의 코드들이 'module.xxx' 형태의
#  절대경로 import를 쓰고 있어서, team2 폴더가 경로에 있어야 정상 동작함)
_TEAM2_DIR = Path(__file__).resolve().parent
if str(_TEAM2_DIR) not in sys.path:
    sys.path.append(str(_TEAM2_DIR))

from vulnerability_service import analyze_services          # noqa: E402
from module.service_analysis_module import (                # noqa: E402
    flatten_team1_scan_output,
)


# ── ① 입력 변환: nmap 결과 -> 팀2 서비스 형식 ──────────────────────────
def _parse_raw_text(scan_input: str) -> list[dict[str, Any]]:
    """
    사용자가 직접 붙여넣은 nmap 텍스트(예: '22/tcp open ssh OpenSSH 7.4')를
    팀2 서비스 형식으로 변환한다. (팀1 JSON이 아닌 경우의 대체 경로)
    """
    services: list[dict[str, Any]] = []
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


def _extract_services(scan_input: Any) -> list[dict[str, Any]]:
    """
    scan_input(팀1이 준 JSON 결과 dict, JSON 문자열, 또는 사용자가
    직접 붙여넣은 raw text)을 analyze_services가 받는 서비스 리스트로 변환.

    - 팀1 공식 JSON 포맷(dict/list, 'hosts' 또는 'ports' 포함)이면
      팀2 공식 함수(flatten_team1_scan_output)를 그대로 사용한다.
    - 그 외(사용자가 nmap 텍스트를 직접 붙여넣은 경우)는 자체 파서를 쓴다.
    """
    scan_data: Any = None
    if isinstance(scan_input, (dict, list)):
        scan_data = scan_input
    elif isinstance(scan_input, str):
        try:
            scan_data = json.loads(scan_input.strip())
        except json.JSONDecodeError:
            scan_data = None

    if scan_data is not None:
        try:
            return flatten_team1_scan_output(scan_data)
        except ValueError:
            # 팀1 형식이 아니면 raw text 파서로 대체 시도
            pass

    return _parse_raw_text(scan_input)


# ── ② 출력 변환: 팀2 결과 -> 대시보드 표시 형식 ─────────────────────────
def _to_dashboard_format(team2_result: dict[str, Any]) -> list[dict[str, Any]]:
    """
    팀2 analyze_services 결과(team3_records)를 대시보드 카드 형식으로 변환.

    [참고] 위험도 예측(predicted_risk)은 팀3 모델이 아직 연동되지 않아
    CVSS 점수로 임시 계산한다. 팀3 predict_priority() 연동 시
    이 함수의 predicted_risk/priority_rank 계산 부분을 팀3 결과값으로 교체하면 된다.
    """
    cves: list[dict[str, Any]] = []
    for rec in team2_result.get("team3_records", []):
        cvss = rec.get("cvss_score")
        cves.append({
            "port": rec.get("port"),
            "service": rec.get("product") or rec.get("service") or "",
            "version": rec.get("version") or "",
            "cve_id": rec.get("cve_id"),
            "cvss": cvss,
            "epss": 0.0,                              # 팀3 값 (임시)
            "kev": False,                             # 팀3 값 (임시)
            "predicted_risk": round(cvss / 10, 2),    # 팀3 연동 전 임시 위험도(CVSS 기반)
            "priority_rank": 0,
            "description": rec.get("description", ""),
            "fix": "대응방안은 팀3 챗봇 연동 후 표시됩니다.",
        })

    cves.sort(key=lambda c: c["predicted_risk"], reverse=True)
    for i, c in enumerate(cves, start=1):
        c["priority_rank"] = i
    return cves


# ── ③ app.py가 호출할 단일 진입점 ──────────────────────────────────────
def run_vulnerability_scan(scan_input: Any, max_cves: int = 5) -> list[dict[str, Any]]:
    """
    nmap 스캔 결과(팀1 JSON 또는 사용자가 붙여넣은 텍스트)를 받아
    CVE 분석까지 마친 뒤, 대시보드 표시용 리스트를 반환한다.

    app.py에서는 이 함수 하나만 부르면 된다:
        cves = run_vulnerability_scan(scan_input)
    """
    services = _extract_services(scan_input)
    if not services:
        return []

    team2_result = analyze_services(services, max_cves=max_cves)
    return _to_dashboard_format(team2_result)