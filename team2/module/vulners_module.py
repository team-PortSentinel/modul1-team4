from __future__ import annotations

import json
import os
import re
import time
from dataclasses import dataclass
from typing import Any, Iterable

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from .schemas import CVSSInfo, VulnerabilityRecord


class VulnersClientError(RuntimeError):
    """Vulners API 요청 또는 응답 처리 오류."""


@dataclass(frozen=True, slots=True)
class _CacheEntry:
    expires_at: float
    data: dict[str, Any]


AUDIT_SOFTWARE_URL = "https://vulners.com/api/v4/audit/software"
SEARCH_BY_ID_URL = "https://vulners.com/api/v3/search/id"
SEARCH_LUCENE_URL = "https://vulners.com/api/v3/search/lucene"

_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)
_CWE_RE = re.compile(r"^CWE-(?:\d+|Other|noinfo)$", re.IGNORECASE)


class VulnersClient:
    """
    Vulners REST API 클라이언트

    처리 흐름:
    1. Software Audit API로 제품 및 버전에 해당하는 취약점 ID 조회
    2. 확인된 CVE ID를 Search by ID API로 일괄 상세 조회
    3. 응답 메모리 캐시로 반복 호출 감소
    """

    def __init__(
        self,
        api_key: str | None = None,
        timeout: float | None = None,
        cache_ttl_seconds: int = 900,
    ) -> None:
        self.api_key = api_key or os.getenv("VULNERS_API_KEY") or None
        if not self.api_key:
            raise ValueError(
                "VULNERS_API_KEY가 설정되지 않았습니다. "
                "환경변수 또는 VulnersClient(api_key=...)로 전달하세요."
            )

        self.timeout = timeout or float(
            os.getenv("VULNERS_TIMEOUT_SECONDS", "25")
        )
        self.cache_ttl_seconds = cache_ttl_seconds
        self._cache: dict[tuple[str, str], _CacheEntry] = {}

        retry = Retry(
            total=3,
            connect=3,
            read=3,
            status=3,
            backoff_factor=0.8,
            status_forcelist=(429, 500, 502, 503, 504),
            allowed_methods=frozenset({"POST"}),
            respect_retry_after_header=True,
        )

        adapter = HTTPAdapter(max_retries=retry)

        self.session = requests.Session()
        self.session.mount("https://", adapter)
        self.session.headers.update(
            {
                "Accept": "application/json",
                "Content-Type": "application/json",
                "X-Api-Key": self.api_key,
                "User-Agent": (
                    "SK-Shieldus-Rookies-Team2-"
                    "Vulnerability-Analyzer/0.3"
                ),
            }
        )

    @staticmethod
    def _cache_key(
        url: str,
        payload: dict[str, Any],
    ) -> tuple[str, str]:
        normalized = json.dumps(
            payload,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        return url, normalized

    def _post(
        self,
        url: str,
        payload: dict[str, Any],
    ) -> dict[str, Any]:
        key = self._cache_key(url, payload)
        now = time.time()

        cached = self._cache.get(key)
        if cached and cached.expires_at > now:
            return cached.data

        try:
            response = self.session.post(
                url,
                json=payload,
                timeout=self.timeout,
            )
            response.raise_for_status()
        except requests.Timeout as exc:
            raise VulnersClientError(
                f"Vulners API 요청 시간이 초과되었습니다: {exc}"
            ) from exc
        except requests.ConnectionError as exc:
            raise VulnersClientError(
                f"Vulners API에 연결하지 못했습니다: {exc}"
            ) from exc
        except requests.RequestException as exc:
            message = ""
            response_obj = getattr(exc, "response", None)
            if response_obj is not None:
                message = response_obj.text[:500]

            suffix = f" · {message}" if message else ""
            raise VulnersClientError(
                f"Vulners API 요청 실패: {exc}{suffix}"
            ) from exc

        try:
            data = response.json()
        except ValueError as exc:
            raise VulnersClientError(
                "Vulners API가 JSON이 아닌 응답을 반환했습니다."
            ) from exc

        if not isinstance(data, dict):
            raise VulnersClientError(
                "Vulners API 응답 최상위 형식이 객체가 아닙니다."
            )

        self._cache[key] = _CacheEntry(
            expires_at=now + self.cache_ttl_seconds,
            data=data,
        )
        return data

    def audit_software(
        self,
        *,
        product: str,
        version: str | None,
        vendor: str | None = None,
        cpe: str | None = None,
        match: str = "partial",
    ) -> dict[str, Any]:
        """제품·버전 또는 CPE를 Software Audit API에 전달한다."""
        if cpe:
            software: list[str | dict[str, Any]] = [cpe]
        else:
            product = product.strip()
            if not product:
                raise ValueError("제품명은 비어 있을 수 없습니다.")

            software_item: dict[str, Any] = {
                "part": "a",
                "product": product,
            }

            if vendor and vendor.strip():
                software_item["vendor"] = vendor.strip()
            if version and version.strip():
                software_item["version"] = version.strip()

            software = [software_item]

        payload = {
            "software": software,
            "match": match,
            "fields": [
                "title",
                "short_description",
                "description",
                "type",
                "href",
                "published",
                "modified",
                "metrics",
                "cvelist",
                "cvelistMetrics",
                "references",
                "cvss2",
                "cvss3",
                "cvss4",
                "epss",
                "exploitation",
                "webApplicability",
                "exploits",
            ],
        }
        return self._post(AUDIT_SOFTWARE_URL, payload)

    def get_documents_by_ids(
        self,
        cve_ids: list[str],
    ) -> dict[str, dict[str, Any]]:
        """여러 CVE를 한 번에 상세 조회한다."""
        normalized_ids = sorted(
            {
                cve_id.strip().upper()
                for cve_id in cve_ids
                if _CVE_RE.match(cve_id.strip())
            }
        )

        if not normalized_ids:
            return {}

        payload = {
            "id": normalized_ids,
            "fields": ["*"],
            "references": True,
        }

        data = self._post(SEARCH_BY_ID_URL, payload)
        payload_data = data.get("data", data)

        documents = payload_data.get("documents", {})
        if isinstance(documents, dict):
            return {
                str(key).upper(): value
                for key, value in documents.items()
                if isinstance(value, dict)
            }

        return {}

    def search_cves_by_lucene(
        self,
        query: str,
        max_results: int = 30,
    ) -> list[dict[str, Any]]:
        """Software Audit 결과가 없을 때 사용할 선택적 보조 검색."""
        query = query.strip()
        if not query:
            raise ValueError("Lucene 검색어는 비어 있을 수 없습니다.")

        payload = {
            "query": query,
            "skip": 0,
            "size": max(1, max_results),
            "fields": ["*"],
        }

        data = self._post(SEARCH_LUCENE_URL, payload)
        return _extract_document_list(data)


def _walk(value: Any) -> Iterable[Any]:
    yield value
    if isinstance(value, dict):
        for child in value.values():
            yield from _walk(child)
    elif isinstance(value, list):
        for child in value:
            yield from _walk(child)


def _extract_document_list(data: dict[str, Any]) -> list[dict[str, Any]]:
    candidates: list[dict[str, Any]] = []
    seen: set[str] = set()

    for value in _walk(data):
        if not isinstance(value, dict):
            continue

        document_id = (
            value.get("id")
            or value.get("_id")
            or value.get("bulletinId")
            or value.get("vulnID")
        )
        if not document_id:
            continue

        identifier = str(document_id).strip()
        if not identifier or identifier in seen:
            continue

        if (
            _CVE_RE.match(identifier)
            or value.get("cvelist")
            or str(value.get("type", "")).lower() == "cve"
        ):
            seen.add(identifier)
            candidates.append(value)

    return candidates


def _extract_cve_ids(data: dict[str, Any]) -> list[str]:
    cve_ids: set[str] = set()

    for value in _walk(data):
        if isinstance(value, str):
            normalized = value.strip().upper()
            if _CVE_RE.match(normalized):
                cve_ids.add(normalized)

        elif isinstance(value, dict):
            for key in ("id", "_id", "vulnID", "bulletinId"):
                raw_id = value.get(key)
                if isinstance(raw_id, str):
                    normalized = raw_id.strip().upper()
                    if _CVE_RE.match(normalized):
                        cve_ids.add(normalized)

            raw_cve_list = (
                value.get("cvelist")
                or value.get("cveList")
                or value.get("cves")
            )
            if isinstance(raw_cve_list, list):
                for item in raw_cve_list:
                    if isinstance(item, str):
                        normalized = item.strip().upper()
                        if _CVE_RE.match(normalized):
                            cve_ids.add(normalized)

    return sorted(cve_ids)


def _first_non_empty(*values: Any) -> Any:
    for value in values:
        if value not in (None, "", [], {}):
            return value
    return None


def _to_float(value: Any) -> float | None:
    try:
        if value is None or value == "":
            return None
        return float(value)
    except (TypeError, ValueError):
        return None


def _severity_from_score(score: float | None) -> str | None:
    if score is None:
        return None
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    if score > 0:
        return "LOW"
    return "NONE"


def _parse_vector(vector: str | None) -> dict[str, str | None]:
    result: dict[str, str | None] = {
        "attack_vector": None,
        "attack_complexity": None,
        "privileges_required": None,
        "user_interaction": None,
        "scope": None,
        "confidentiality_impact": None,
        "integrity_impact": None,
        "availability_impact": None,
    }
    if not vector:
        return result

    values: dict[str, str] = {}
    for component in vector.split("/"):
        if ":" not in component:
            continue
        key, raw_value = component.split(":", 1)
        values[key] = raw_value

    result["attack_vector"] = {
        "N": "NETWORK",
        "A": "ADJACENT",
        "L": "LOCAL",
        "P": "PHYSICAL",
    }.get(values.get("AV", ""))
    result["attack_complexity"] = {
        "L": "LOW",
        "H": "HIGH",
    }.get(values.get("AC", ""))
    result["privileges_required"] = {
        "N": "NONE",
        "L": "LOW",
        "H": "HIGH",
    }.get(values.get("PR", ""))
    result["user_interaction"] = {
        "N": "NONE",
        "R": "REQUIRED",
        "P": "PASSIVE",
        "A": "ACTIVE",
    }.get(values.get("UI", ""))
    result["scope"] = {
        "U": "UNCHANGED",
        "C": "CHANGED",
    }.get(values.get("S", ""))

    impact_map = {"N": "NONE", "L": "LOW", "H": "HIGH"}
    result["confidentiality_impact"] = impact_map.get(values.get("C", ""))
    result["integrity_impact"] = impact_map.get(values.get("I", ""))
    result["availability_impact"] = impact_map.get(values.get("A", ""))
    return result


def _find_metric_candidates(document: dict[str, Any]) -> list[dict[str, Any]]:
    candidates: list[dict[str, Any]] = []

    for value in _walk(document):
        if not isinstance(value, dict):
            continue

        vector = _first_non_empty(
            value.get("vectorString"),
            value.get("vector"),
            value.get("cvssVector"),
        )
        score = _first_non_empty(
            value.get("baseScore"),
            value.get("score"),
            value.get("cvssScore"),
        )
        version = _first_non_empty(
            value.get("version"),
            value.get("cvssVersion"),
        )

        if vector or score is not None:
            candidates.append(
                {
                    "version": version,
                    "score": score,
                    "severity": _first_non_empty(
                        value.get("baseSeverity"),
                        value.get("severity"),
                        value.get("severityText"),
                    ),
                    "vector": vector,
                    "source": _first_non_empty(
                        value.get("source"),
                        value.get("provider"),
                    ),
                    "raw": value,
                }
            )

    return candidates


def extract_cvss(document: dict[str, Any]) -> CVSSInfo:
    candidates = _find_metric_candidates(document)

    def priority(item: dict[str, Any]) -> tuple[int, float]:
        version_text = str(item.get("version") or "")
        vector_text = str(item.get("vector") or "")

        if "4.0" in version_text or vector_text.startswith("CVSS:4.0"):
            version_rank = 4
        elif "3.1" in version_text or vector_text.startswith("CVSS:3.1"):
            version_rank = 3
        elif "3.0" in version_text or vector_text.startswith("CVSS:3.0"):
            version_rank = 2
        else:
            version_rank = 1

        score = _to_float(item.get("score"))
        return version_rank, score if score is not None else -1.0

    if not candidates:
        return CVSSInfo()

    selected = max(candidates, key=priority)
    score = _to_float(selected.get("score"))
    vector = str(selected.get("vector")) if selected.get("vector") else None
    parsed_vector = _parse_vector(vector)

    version = selected.get("version")
    if not version and vector and vector.startswith("CVSS:"):
        version = vector.split("/", 1)[0].replace("CVSS:", "")

    severity = selected.get("severity")
    if isinstance(severity, str):
        severity = severity.upper()
    else:
        severity = _severity_from_score(score)

    raw = selected.get("raw") or {}

    return CVSSInfo(
        version=str(version) if version else None,
        base_score=score,
        severity=severity,
        vector=vector,
        source=(
            str(selected.get("source"))
            if selected.get("source")
            else "Vulners"
        ),
        metric_type="Primary",
        attack_vector=_first_non_empty(
            raw.get("attackVector"), parsed_vector["attack_vector"]
        ),
        attack_complexity=_first_non_empty(
            raw.get("attackComplexity"), parsed_vector["attack_complexity"]
        ),
        privileges_required=_first_non_empty(
            raw.get("privilegesRequired"), parsed_vector["privileges_required"]
        ),
        user_interaction=_first_non_empty(
            raw.get("userInteraction"), parsed_vector["user_interaction"]
        ),
        scope=_first_non_empty(raw.get("scope"), parsed_vector["scope"]),
        confidentiality_impact=_first_non_empty(
            raw.get("confidentialityImpact"),
            parsed_vector["confidentiality_impact"],
        ),
        integrity_impact=_first_non_empty(
            raw.get("integrityImpact"), parsed_vector["integrity_impact"]
        ),
        availability_impact=_first_non_empty(
            raw.get("availabilityImpact"), parsed_vector["availability_impact"]
        ),
    )


def extract_cwes(document: dict[str, Any]) -> list[str]:
    cwes: set[str] = set()

    for value in _walk(document):
        if isinstance(value, str):
            for match in re.findall(
                r"CWE-(?:\d+|Other|noinfo)",
                value,
                flags=re.IGNORECASE,
            ):
                normalized = match.upper().replace(
                    "CWE-NOINFO", "CWE-noinfo"
                )
                if _CWE_RE.match(normalized):
                    cwes.add(normalized)

    return sorted(cwes)


def extract_description(document: dict[str, Any]) -> str:
    value = _first_non_empty(
        document.get("description"),
        document.get("short_description"),
        document.get("shortDescription"),
        document.get("title"),
    )
    return str(value) if value else "설명 없음"


def extract_references(
    document: dict[str, Any],
    limit: int = 15,
) -> list[dict[str, Any]]:
    references: list[dict[str, Any]] = []
    seen_urls: set[str] = set()

    def add_reference(
        url: Any,
        source: Any = None,
        tags: Any = None,
    ) -> None:
        if not isinstance(url, str):
            return
        normalized_url = url.strip()
        if not normalized_url or normalized_url in seen_urls:
            return

        seen_urls.add(normalized_url)
        references.append(
            {
                "url": normalized_url,
                "source": str(source) if source else "Vulners",
                "tags": list(tags) if isinstance(tags, list) else [],
            }
        )

    add_reference(document.get("href"), document.get("type"), ["Vulners"])
    add_reference(
        document.get("sourceHref"),
        document.get("type"),
        ["Original Source"],
    )

    raw_references = document.get("references")
    if isinstance(raw_references, list):
        for item in raw_references:
            if isinstance(item, str):
                add_reference(item)
            elif isinstance(item, dict):
                add_reference(
                    item.get("url") or item.get("href"),
                    item.get("source"),
                    item.get("tags"),
                )

    return references[:limit]


def normalize_vulnerability(
    document: dict[str, Any],
    *,
    matched_by_audit: bool = True,
) -> VulnerabilityRecord:
    raw_id = _first_non_empty(
        document.get("id"),
        document.get("_id"),
        document.get("vulnID"),
        document.get("bulletinId"),
    )

    cve_id = str(raw_id or "UNKNOWN").upper()

    if not _CVE_RE.match(cve_id):
        cve_list = document.get("cvelist") or document.get("cveList")
        if isinstance(cve_list, list):
            first_cve = next(
                (
                    str(item).upper()
                    for item in cve_list
                    if isinstance(item, str) and _CVE_RE.match(item)
                ),
                None,
            )
            if first_cve:
                cve_id = first_cve

    applicability = "affected" if matched_by_audit else "unknown"
    applicability_reason = (
        "Vulners Software Audit API가 입력한 제품·버전에 해당 취약점을 매칭했습니다."
        if matched_by_audit
        else "Vulners 검색 결과이므로 실제 설치 버전 적용 여부를 추가 검토해야 합니다."
    )

    timestamps = document.get("timestamps")
    if not isinstance(timestamps, dict):
        timestamps = {}

    return VulnerabilityRecord(
        cve_id=cve_id,
        description=extract_description(document),
        cvss=extract_cvss(document),
        cwe_ids=extract_cwes(document),
        affected_products=[],
        references=extract_references(document),
        published=_first_non_empty(
            document.get("published"), timestamps.get("published")
        ),
        last_modified=_first_non_empty(
            document.get("modified"),
            document.get("lastModified"),
            timestamps.get("modified"),
        ),
        vuln_status="Analyzed",
        applicability=applicability,
        applicability_reason=applicability_reason,
    )


class VulnersProvider:
    """
    VulnerabilityService에서 사용할 Vulners 공급자.

    NVDProvider와 동일한 search_vulnerabilities() 인터페이스를 제공한다.
    """

    provider_name = "vulners"

    def __init__(
        self,
        client: VulnersClient | None = None,
        match: str = "partial",
        lucene_fallback: bool = False,
    ) -> None:
        if match not in {"partial", "full"}:
            raise ValueError("match는 'partial' 또는 'full'이어야 합니다.")

        self.client = client or VulnersClient()
        self.match = match
        self.lucene_fallback = lucene_fallback

    def search_vulnerabilities(
        self,
        product: str,
        version: str | None,
        vendor: str | None = None,
        cpe: str | None = None,
        max_results: int = 30,
    ) -> list[VulnerabilityRecord]:
        """
        제품·버전 또는 CPE 기준으로 취약점을 조회한다.

        기본 요청 수:
        - Software Audit API 1회
        - CVE 상세 일괄 조회 1회
        """
        audit_data = self.client.audit_software(
            product=product,
            version=version,
            vendor=vendor,
            cpe=cpe,
            match=self.match,
        )

        cve_ids = _extract_cve_ids(audit_data)[:max_results]

        if cve_ids:
            documents_by_id = self.client.get_documents_by_ids(cve_ids)
            records: list[VulnerabilityRecord] = []

            for cve_id in cve_ids:
                document = documents_by_id.get(cve_id)
                if not document:
                    continue
                records.append(
                    normalize_vulnerability(document, matched_by_audit=True)
                )

            if records:
                return _sort_records(records)[:max_results]

        embedded_documents = _extract_document_list(audit_data)
        embedded_records = [
            normalize_vulnerability(document, matched_by_audit=True)
            for document in embedded_documents
            if _document_has_cve(document)
        ]

        if embedded_records:
            return _sort_records(embedded_records)[:max_results]

        if self.lucene_fallback:
            query_parts = ['type:cve', f'"{product}"']
            if version:
                query_parts.append(f'"{version}"')
            if vendor:
                query_parts.append(f'"{vendor}"')

            documents = self.client.search_cves_by_lucene(
                " AND ".join(query_parts),
                max_results=max_results,
            )
            fallback_records = [
                normalize_vulnerability(document, matched_by_audit=False)
                for document in documents
                if _document_has_cve(document)
            ]
            return _sort_records(fallback_records)[:max_results]

        return []


def _document_has_cve(document: dict[str, Any]) -> bool:
    raw_id = _first_non_empty(
        document.get("id"),
        document.get("_id"),
        document.get("vulnID"),
        document.get("bulletinId"),
    )

    if isinstance(raw_id, str) and _CVE_RE.match(raw_id):
        return True

    cve_list = document.get("cvelist") or document.get("cveList")
    return bool(
        isinstance(cve_list, list)
        and any(
            isinstance(item, str) and _CVE_RE.match(item)
            for item in cve_list
        )
    )


def _deduplicate_records(
    records: list[VulnerabilityRecord],
) -> list[VulnerabilityRecord]:
    unique: dict[str, VulnerabilityRecord] = {}

    for record in records:
        current = unique.get(record.cve_id)
        if current is None:
            unique[record.cve_id] = record
            continue

        current_score = (
            current.cvss.base_score
            if current.cvss.base_score is not None
            else -1.0
        )
        new_score = (
            record.cvss.base_score
            if record.cvss.base_score is not None
            else -1.0
        )

        if new_score > current_score:
            unique[record.cve_id] = record

    return list(unique.values())


def _sort_records(
    records: list[VulnerabilityRecord],
) -> list[VulnerabilityRecord]:
    return sorted(
        _deduplicate_records(records),
        key=lambda record: (
            -(
                record.cvss.base_score
                if record.cvss.base_score is not None
                else -1.0
            ),
            record.cve_id,
        ),
    )
