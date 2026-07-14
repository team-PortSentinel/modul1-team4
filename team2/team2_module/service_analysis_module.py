from __future__ import annotations

import re
from typing import Any

from .schemas import ServiceInput, Team3Record, VulnerabilityRecord


_ALIAS_MAP = {
    "apache": ("Apache", "Apache HTTP Server"),
    "apache httpd": ("Apache", "Apache HTTP Server"),
    "httpd": ("Apache", "Apache HTTP Server"),
    "iis": ("Microsoft", "Microsoft Internet Information Services"),
    "microsoft iis": ("Microsoft", "Microsoft Internet Information Services"),
    "openssh": ("OpenBSD", "OpenSSH"),
    "nginx": ("F5", "nginx"),
    "vsftpd": (None, "vsftpd"),
    "mysql": ("Oracle", "MySQL"),
}
_VERSION_RE = re.compile(r"\b(v?\d+(?:\.\d+)+(?:[._+\-]?[a-zA-Z0-9]+)*)\b")


def _clean(value: Any) -> str | None:
    if value is None:
        return None
    text = re.sub(r"\s+", " ", str(value)).strip()
    return text or None


def _split_product_version(text: str | None) -> tuple[str | None, str | None]:
    if not text:
        return None, None
    match = _VERSION_RE.search(text)
    if not match:
        return text.strip(), None
    product = text[: match.start()].strip(" -()") or None
    return product, match.group(1).lstrip("vV")


def normalize_service_input(raw: dict[str, Any] | ServiceInput) -> ServiceInput:
    """팀 1 출력의 키·타입·제품명을 팀 2 표준 형식으로 정규화."""
    if isinstance(raw, ServiceInput):
        return raw

    service = _clean(raw.get("service") or raw.get("serviced") or raw.get("name"))
    status = (_clean(raw.get("status") or raw.get("state")) or "unknown").lower()
    product = _clean(raw.get("product"))
    version = _clean(raw.get("version"))
    vendor = _clean(raw.get("vendor"))
    extra_info = _clean(raw.get("extra_info") or raw.get("extrainfo"))

    # 팀 1이 product/version 대신 version 필드 하나에 전체 배너를 넣는 경우 보정
    if version and not product and " " in version:
        guessed_product, guessed_version = _split_product_version(version)
        if guessed_product:
            product = guessed_product
        if guessed_version:
            version = guessed_version

    # product에 버전이 붙어 있는 경우 분리
    if product:
        guessed_product, guessed_version = _split_product_version(product)
        if guessed_product and guessed_version:
            product = guessed_product
            version = version or guessed_version

    alias_key = (product or service or "").lower()
    if alias_key in _ALIAS_MAP:
        alias_vendor, alias_product = _ALIAS_MAP[alias_key]
        product = alias_product
        vendor = vendor or alias_vendor

    if not service:
        raise ValueError("service 필드는 필수입니다.")
    try:
        port = int(raw.get("port"))
    except (TypeError, ValueError) as exc:
        raise ValueError("port는 정수로 변환 가능해야 합니다.") from exc

    return ServiceInput(
        host=_clean(raw.get("host") or raw.get("ip")),
        port=port,
        protocol=_clean(raw.get("protocol") or raw.get("proto")) or "tcp",
        status=status,
        service=service,
        product=product or service,
        version=version,
        vendor=vendor,
        extra_info=extra_info,
    )

#### 추가
def flatten_team1_scan_output(payload: Any) -> list[dict[str, Any]]:
    """팀 1의 호스트 단위 Nmap JSON을 서비스 단위 목록으로 평탄화합니다.

    지원 입력:
    - 단일 호스트 dict: {ip, hostname, status, os, ports:[...]}
    - 호스트 dict의 list
    - 이미 평탄화된 서비스 dict의 list
    - {"hosts": [...]} 또는 {"results": [...]} 래퍼
    """
    if isinstance(payload, dict):
        if isinstance(payload.get("hosts"), list):
            payload = payload["hosts"]
        elif isinstance(payload.get("results"), list):
            payload = payload["results"]
        else:
            payload = [payload]

    if not isinstance(payload, list):
        raise ValueError("팀 1 출력은 JSON 객체 또는 객체 배열이어야 합니다.")

    flattened: list[dict[str, Any]] = []
    for index, item in enumerate(payload):
        if not isinstance(item, dict):
            raise ValueError(f"{index + 1}번째 항목이 JSON 객체가 아닙니다.")

        ports = item.get("ports")
        if not isinstance(ports, list):
            # 기존 평탄 서비스 입력과의 하위 호환
            flattened.append(dict(item))
            continue

        host_ip = _clean(item.get("ip") or item.get("host"))
        hostname = _clean(item.get("hostname"))
        host_status = (_clean(item.get("status")) or "unknown").lower()
        os_info = item.get("os") if isinstance(item.get("os"), dict) else {}

        for port_item in ports:
            if not isinstance(port_item, dict):
                continue
            port_state = (_clean(port_item.get("state") or port_item.get("status")) or "unknown").lower()
            flattened.append(
                {
                    "host": host_ip,
                    "ip": host_ip,
                    "hostname": hostname,
                    "host_status": host_status,
                    "os_name": _clean(os_info.get("name")),
                    "os_accuracy": os_info.get("accuracy"),
                    "port": port_item.get("port"),
                    "protocol": _clean(port_item.get("protocol")) or "tcp",
                    "status": port_state,
                    "state": port_state,
                    "service": _clean(port_item.get("service")),
                    "product": _clean(port_item.get("product")),
                    "version": _clean(port_item.get("version")),
                    "vendor": _clean(port_item.get("vendor")),
                    "extra_info": _clean(port_item.get("extra_info") or port_item.get("extrainfo")),
                }
            )

    return flattened
#### 추가


def filter_applicable_vulnerabilities(items: list[VulnerabilityRecord]) -> list[VulnerabilityRecord]:
    """명확히 미적용인 CVE만 제외하고 나머지는 보존."""
    unique: dict[str, VulnerabilityRecord] = {}
    for item in items:
        if item.applicability == "not_affected":
            continue
        unique[item.cve_id] = item
    priority = {"affected": 0, "needs_review": 1, "unknown": 2}
    return sorted(
        unique.values(),
        key=lambda x: (
            priority.get(x.applicability, 9),
            -(x.cvss.base_score if x.cvss.base_score is not None else -1.0),
            x.cve_id,
        ),
    )


def build_team3_output(service: ServiceInput, vulnerabilities: list[VulnerabilityRecord]) -> list[dict[str, Any]]:
    """팀 3 학습/추론 컬럼으로 평탄화."""
    rows: list[dict[str, Any]] = []
    for vuln in vulnerabilities:
        rows.append(
            Team3Record(
                cve_id=vuln.cve_id,
                cvss_score=vuln.cvss.base_score,
                severity=vuln.cvss.severity,
                attack_vector=vuln.cvss.attack_vector,
                attack_complexity=vuln.cvss.attack_complexity,
                privileges_required=vuln.cvss.privileges_required,
                user_interaction=vuln.cvss.user_interaction,
                cwe=vuln.cwe_ids[0] if vuln.cwe_ids else None,
                description=vuln.description,
                host=service.host,
                port=service.port,
                service=service.service,
                product=service.product,
                version=service.version,
                applicability=vuln.applicability,
            ).to_dict()
        )
    return rows
