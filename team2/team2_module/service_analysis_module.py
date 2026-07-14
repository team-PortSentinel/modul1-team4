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

#### 추가from __future__ import annotations

from typing import Any


def flatten_team1_scan_output(
    scan_output: dict[str, Any] | list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """
    팀 1의 Nmap JSON 결과를 서비스 단위 리스트로 평탄화한다.

    지원 형식:
    1. 단일 호스트 dict
    2. 호스트 dict 리스트
    3. {"success": true, "hosts": [...]} 형태
    4. 이미 평탄화된 서비스 dict 리스트
    """

    # 새 형식:
    # {
    #   "success": true,
    #   "hosts": [...]
    # }
    if isinstance(scan_output, dict) and isinstance(scan_output.get("hosts"), list):
        hosts = scan_output["hosts"]

    # 기존 단일 호스트 형식
    elif isinstance(scan_output, dict) and isinstance(scan_output.get("ports"), list):
        hosts = [scan_output]

    # 호스트 목록 또는 이미 평탄화된 목록
    elif isinstance(scan_output, list):
        hosts = scan_output

    else:
        raise ValueError(
            "지원하지 않는 팀 1 출력 형식입니다. "
            "'hosts' 또는 'ports' 배열이 필요합니다."
        )

    flattened: list[dict[str, Any]] = []

    for host_item in hosts:
        if not isinstance(host_item, dict):
            continue

        # 이미 평탄화된 서비스 형식이면 그대로 정리
        if "ports" not in host_item:
            flattened.append(
                {
                    "host": host_item.get("host") or host_item.get("ip"),
                    "ip": host_item.get("ip") or host_item.get("host"),
                    "hostname": _none_if_blank(host_item.get("hostname")),
                    "host_status": _none_if_blank(
                        host_item.get("host_status")
                        or host_item.get("status")
                    ),
                    "os_name": _none_if_blank(host_item.get("os_name")),
                    "os_accuracy": host_item.get("os_accuracy"),
                    "port": host_item.get("port"),
                    "protocol": _none_if_blank(host_item.get("protocol")),
                    "status": _none_if_blank(
                        host_item.get("status")
                        or host_item.get("state")
                    ),
                    "state": _none_if_blank(
                        host_item.get("state")
                        or host_item.get("status")
                    ),
                    "service": _none_if_blank(
                        host_item.get("service")
                        or host_item.get("serviced")
                    ),
                    "product": _none_if_blank(host_item.get("product")),
                    "version": _none_if_blank(host_item.get("version")),
                    "vendor": _none_if_blank(host_item.get("vendor")),
                    "extra_info": _none_if_blank(
                        host_item.get("extra_info")
                        or host_item.get("extrainfo")
                    ),
                    "full_info": _none_if_blank(
                        host_item.get("full_info")
                        or host_item.get("fullinfo")
                    ),
                }
            )
            continue

        ip = _none_if_blank(host_item.get("ip"))
        hostname = _none_if_blank(host_item.get("hostname"))
        host_status = _none_if_blank(host_item.get("status"))

        os_info = host_item.get("os") or {}
        os_name = _none_if_blank(os_info.get("name"))
        os_accuracy = os_info.get("accuracy")

        ports = host_item.get("ports") or []

        for port_item in ports:
            if not isinstance(port_item, dict):
                continue

            flattened.append(
                {
                    "host": ip,
                    "ip": ip,
                    "hostname": hostname,
                    "host_status": host_status,
                    "os_name": os_name,
                    "os_accuracy": os_accuracy,
                    "port": port_item.get("port"),
                    "protocol": _none_if_blank(port_item.get("protocol")),
                    "status": _none_if_blank(port_item.get("state")),
                    "state": _none_if_blank(port_item.get("state")),
                    "service": _none_if_blank(port_item.get("service")),
                    "product": _none_if_blank(port_item.get("product")),
                    "version": _none_if_blank(port_item.get("version")),
                    "vendor": _none_if_blank(port_item.get("vendor")),
                    "extra_info": _none_if_blank(
                        port_item.get("extrainfo")
                        or port_item.get("extra_info")
                    ),
                    "full_info": _none_if_blank(
                        port_item.get("fullinfo")
                        or port_item.get("full_info")
                    ),
                }
            )

    return flattened


def _none_if_blank(value: Any) -> Any:
    """
    빈 문자열, 공백 문자열, '정보 없음'을 None으로 변환한다.
    """
    if value is None:
        return None

    if isinstance(value, str):
        cleaned = value.strip()

        if not cleaned or cleaned == "정보 없음":
            return None

        return cleaned

    return value
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
