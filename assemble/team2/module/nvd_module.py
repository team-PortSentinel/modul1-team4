from __future__ import annotations

import os
import re
import time
from dataclasses import dataclass
from typing import Any, Iterable

import requests
from packaging.version import InvalidVersion, Version
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from .schemas import AffectedProduct, CPECandidate, CVSSInfo, ServiceInput, VulnerabilityRecord


class NVDClientError(RuntimeError):
    """NVD API 요청 또는 응답 처리 오류."""


@dataclass(frozen=True, slots=True)
class _CacheEntry:
    expires_at: float
    data: dict[str, Any]


CVE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CPE_URL = "https://services.nvd.nist.gov/rest/json/cpes/2.0"
_CWE_RE = re.compile(r"^CWE-(?:\d+|Other|noinfo)$", re.IGNORECASE)


class NVDClient:
    """NVD CVE/CPE API 2.0 클라이언트."""

    def __init__(
        self,
        api_key: str | None = None,
        timeout: float | None = None,
        cache_ttl_seconds: int = 900,
    ) -> None:
        self.api_key = api_key or os.getenv("NVD_API_KEY") or None
        self.timeout = timeout or float(os.getenv("NVD_TIMEOUT_SECONDS", "25"))
        self.cache_ttl_seconds = cache_ttl_seconds
        self.min_request_interval = float(os.getenv("NVD_MIN_REQUEST_INTERVAL", "6.0" if not self.api_key else "0.7"))
        self._last_request_at = 0.0
        self._cache: dict[tuple[str, tuple[tuple[str, str], ...]], _CacheEntry] = {}

        retry = Retry(
            total=3,
            connect=3,
            read=3,
            status=3,
            backoff_factor=1.0,
            status_forcelist=(500, 502, 503, 504),
            allowed_methods=frozenset({"GET"}),
            respect_retry_after_header=True,
        )
        adapter = HTTPAdapter(max_retries=retry)
        self.session = requests.Session()
        self.session.mount("https://", adapter)
        self.session.headers.update(
            {
                "Accept": "application/json",
                "User-Agent": "SK-Shieldus-Rookies-Team2-Vulnerability-Analyzer/0.2",
            }
        )
        if self.api_key:
            self.session.headers["apiKey"] = self.api_key
    
    def _wait_for_rate_limit(self) -> None:
        """
        NVD API 실제 호출 사이에 최소 간격을 유지한다.
        캐시 응답에는 적용하지 않는다.
        """
        elapsed = time.monotonic() - self._last_request_at
        remaining = self.min_request_interval - elapsed

        if remaining > 0:
            time.sleep(remaining)

    @staticmethod
    def _cache_key(url: str, params: dict[str, Any]) -> tuple[str, tuple[tuple[str, str], ...]]:
        return url, tuple(sorted((str(k), str(v)) for k, v in params.items()))

    def _get(self, url: str, params: dict[str, Any]) -> dict[str, Any]:
        key = self._cache_key(url, params)
        now = time.time()
        cached = self._cache.get(key)
        if cached and cached.expires_at > now:
            return cached.data
        
        self._wait_for_rate_limit()

        try:
            response = self.session.get(url,params=params, timeout=self.timeout)

            self._last_request_at = time.monotonic()

            if response.status_code == 429:
                retry_after = response.headers.get("Retry-After")

                try:
                    wait_seconds = float(retry_after)
                except (TypeError, ValueError):
                    wait_seconds = 30.0

                print(
                    f"NVD 호출 제한 발생: "
                    f"{wait_seconds:.1f}초 대기 후 재시도"
                )

                time.sleep(wait_seconds)

                response = self.session.get(
                    url,
                    params=params,
                    timeout=self.timeout,
                )

                self._last_request_at = time.monotonic()

            response.raise_for_status()

        except requests.RequestException as exc:
            raise NVDClientError(
                f"NVD API 요청 실패: {exc}"
            ) from exc

        try:
            data = response.json()
        except ValueError as exc:
            raise NVDClientError("NVD API가 JSON이 아닌 응답을 반환했습니다.") from exc

        self._cache[key] = _CacheEntry(now + self.cache_ttl_seconds, data)
        return data

    def search_cpes(self, keyword: str, max_results: int = 10) -> list[dict[str, Any]]:
        keyword = keyword.strip()
        if not keyword:
            raise ValueError("CPE 검색어는 비어 있을 수 없습니다.")
        data = self._get(CPE_URL, {"keywordSearch": keyword, "resultsPerPage": max(1, min(max_results, 100))})
        return list(data.get("products", []))

    def search_cves_by_cpe(self, cpe_name: str, max_results: int = 30) -> list[dict[str, Any]]:
        data = self._get(CVE_URL, {"cpeName": cpe_name, "resultsPerPage": max(1, min(max_results, 2000))})
        return list(data.get("vulnerabilities", []))

    def search_cves_by_keyword(self, keyword: str, max_results: int = 30) -> list[dict[str, Any]]:
        data = self._get(CVE_URL, {"keywordSearch": keyword, "resultsPerPage": max(1, min(max_results, 2000))})
        return list(data.get("vulnerabilities", []))

    def get_cve(self, cve_id: str) -> dict[str, Any] | None:
        data = self._get(CVE_URL, {"cveId": cve_id.strip().upper()})
        rows = data.get("vulnerabilities", [])
        return rows[0] if rows else None


def _tokenize(value: str) -> set[str]:
    return set(re.findall(r"[a-z0-9]+", value.lower()))


def _candidate_title(raw_product: dict[str, Any]) -> str:
    cpe = raw_product.get("cpe", raw_product)
    titles = cpe.get("titles", [])
    for item in titles:
        if item.get("lang") == "en":
            return str(item.get("title", ""))
    return str(titles[0].get("title", "")) if titles else str(cpe.get("cpeName", ""))


def score_cpe_candidate(service: ServiceInput, cpe_name: str, title: str) -> float:
    candidate_text = f"{title} {cpe_name}".lower()
    product_tokens = _tokenize(service.product or service.service)
    candidate_tokens = _tokenize(candidate_text)
    if not product_tokens:
        return 0.0

    product_overlap = len(product_tokens & candidate_tokens) / len(product_tokens)
    vendor_bonus = 0.15 if service.vendor and service.vendor.lower() in candidate_text else 0.0
    version_bonus = 0.15 if service.version and service.version.lower() in candidate_text else 0.0
    return round(min(1.0, product_overlap * 0.7 + vendor_bonus + version_bonus), 4)


def normalize_cpe_candidates(raw_products: list[dict[str, Any]], service: ServiceInput) -> list[CPECandidate]:
    candidates: list[CPECandidate] = []
    for raw in raw_products:
        cpe = raw.get("cpe", raw)
        cpe_name = str(cpe.get("cpeName", "")).strip()
        if not cpe_name:
            continue
        title = _candidate_title(raw)
        candidates.append(
            CPECandidate(
                cpe_name=cpe_name,
                title=title,
                deprecated=bool(cpe.get("deprecated", False)),
                match_score=score_cpe_candidate(service, cpe_name, title),
            )
        )
    return sorted(candidates, key=lambda x: (x.deprecated, -x.match_score, x.title))


def select_best_cpe(candidates: list[CPECandidate], minimum_score: float = 0.55) -> CPECandidate | None:
    return next((x for x in candidates if not x.deprecated and x.match_score >= minimum_score), None)


def parse_cpe23(cpe: str) -> dict[str, str]:
    parts = cpe.split(":")
    if len(parts) < 6 or parts[:2] != ["cpe", "2.3"]:
        return {}
    return {"part": parts[2], "vendor": parts[3], "product": parts[4], "version": parts[5]}


def same_product(query_cpe: str, affected_cpe: str) -> bool:
    query = parse_cpe23(query_cpe)
    affected = parse_cpe23(affected_cpe)
    return bool(query and affected and all(query[k] == affected[k] for k in ("part", "vendor", "product")))


def safe_version(raw: str | None) -> Version | None:
    if not raw or raw in {"*", "-"}:
        return None
    normalized = raw.strip().lstrip("vV")
    try:
        return Version(normalized)
    except InvalidVersion:
        numeric = re.search(r"\d+(?:\.\d+)+", normalized)
        if not numeric:
            return None
        try:
            return Version(numeric.group(0))
        except InvalidVersion:
            return None


def version_is_affected(version: str, product: AffectedProduct, criteria_version: str | None) -> bool | None:
    target = safe_version(version)
    if criteria_version not in {None, "", "*", "-"}:
        exact = safe_version(criteria_version)
        if target is None or exact is None:
            return version == criteria_version
        return target == exact
    if target is None:
        return None

    bounds = (
        (product.version_start_including, "start_including"),
        (product.version_start_excluding, "start_excluding"),
        (product.version_end_including, "end_including"),
        (product.version_end_excluding, "end_excluding"),
    )
    parsed_any = False
    for raw_bound, kind in bounds:
        if not raw_bound:
            continue
        bound = safe_version(raw_bound)
        if bound is None:
            return None
        parsed_any = True
        if kind == "start_including" and target < bound:
            return False
        if kind == "start_excluding" and target <= bound:
            return False
        if kind == "end_including" and target > bound:
            return False
        if kind == "end_excluding" and target >= bound:
            return False
    return True if parsed_any or criteria_version in {"*", "-"} else None


def _english_value(items: Iterable[dict[str, Any]], key: str = "value") -> str | None:
    values = list(items)
    for item in values:
        if item.get("lang") == "en" and item.get(key):
            return str(item[key])
    for item in values:
        if item.get(key):
            return str(item[key])
    return None


def extract_description(cve: dict[str, Any]) -> str:
    return _english_value(cve.get("descriptions", [])) or "설명 없음"


def extract_cwes(cve: dict[str, Any]) -> list[str]:
    cwes: set[str] = set()
    for weakness in cve.get("weaknesses", []):
        for description in weakness.get("description", []):
            value = str(description.get("value", "")).strip()
            if _CWE_RE.match(value):
                cwes.add(value.upper().replace("CWE-NOINFO", "CWE-noinfo"))
    return sorted(cwes)


def extract_cvss(cve: dict[str, Any]) -> CVSSInfo:
    priorities = (("4.0", "cvssMetricV40"), ("3.1", "cvssMetricV31"), ("3.0", "cvssMetricV30"), ("2.0", "cvssMetricV2"))
    metric: dict[str, Any] | None = None
    version: str | None = None
    metrics = cve.get("metrics", {})
    for candidate_version, key in priorities:
        candidates = metrics.get(key) or []
        if candidates:
            metric = next((x for x in candidates if str(x.get("type", "")).lower() == "primary"), candidates[0])
            version = candidate_version
            break
    if not metric:
        return CVSSInfo()

    data = metric.get("cvssData", {})
    return CVSSInfo(
        version=version or data.get("version"),
        base_score=data.get("baseScore"),
        severity=data.get("baseSeverity") or metric.get("baseSeverity"),
        vector=data.get("vectorString"),
        source=metric.get("source"),
        metric_type=metric.get("type"),
        attack_vector=data.get("attackVector") or data.get("accessVector"),
        attack_complexity=data.get("attackComplexity") or data.get("accessComplexity"),
        privileges_required=data.get("privilegesRequired") or data.get("authentication"),
        user_interaction=data.get("userInteraction"),
        scope=data.get("scope"),
        confidentiality_impact=data.get("confidentialityImpact"),
        integrity_impact=data.get("integrityImpact"),
        availability_impact=data.get("availabilityImpact"),
    )


def _walk_nodes(value: Any) -> Iterable[dict[str, Any]]:
    if isinstance(value, dict):
        for match in value.get("cpeMatch", []) or []:
            if isinstance(match, dict):
                yield match
        for key in ("nodes", "children"):
            for child in value.get(key, []) or []:
                yield from _walk_nodes(child)
    elif isinstance(value, list):
        for item in value:
            yield from _walk_nodes(item)


def extract_affected_products(cve: dict[str, Any]) -> list[AffectedProduct]:
    result: list[AffectedProduct] = []
    seen: set[tuple[Any, ...]] = set()
    for match in _walk_nodes(cve.get("configurations", [])):
        criteria = str(match.get("criteria", "")).strip()
        if not criteria:
            continue
        item = AffectedProduct(
            criteria=criteria,
            vulnerable=bool(match.get("vulnerable", False)),
            version_start_including=match.get("versionStartIncluding"),
            version_start_excluding=match.get("versionStartExcluding"),
            version_end_including=match.get("versionEndIncluding"),
            version_end_excluding=match.get("versionEndExcluding"),
        )
        key = tuple(item.to_dict().values())
        if key not in seen:
            seen.add(key)
            result.append(item)
    return result


def determine_applicability(selected_cpe: str | None, version: str | None, products: list[AffectedProduct]) -> tuple[str, str]:
    if not selected_cpe:
        return "unknown", "선택된 CPE가 없습니다."
    if not version:
        return "needs_review", "서비스 버전이 없어 자동 판별할 수 없습니다."
    if not products:
        return "unknown", "NVD에 영향 제품 범위가 없습니다."

    matched = False
    uncertain = False
    for product in products:
        if not product.vulnerable or not same_product(selected_cpe, product.criteria):
            continue
        matched = True
        criteria_version = parse_cpe23(product.criteria).get("version")
        affected = version_is_affected(version, product, criteria_version)
        if affected is True:
            return "affected", "NVD의 제품 및 버전 조건과 일치합니다."
        if affected is None:
            uncertain = True
    if uncertain:
        return "needs_review", "제품은 일치하지만 버전 표현을 자동 비교하기 어렵습니다."
    if matched:
        return "not_affected", "제품은 일치하지만 영향 버전 범위에 포함되지 않습니다."
    return "unknown", "선택된 CPE와 같은 제품을 구성 정보에서 찾지 못했습니다."


def normalize_vulnerability(wrapper: dict[str, Any], selected_cpe: str | None, service_version: str | None) -> VulnerabilityRecord:
    cve = wrapper.get("cve", wrapper)
    products = extract_affected_products(cve)
    applicability, reason = determine_applicability(selected_cpe, service_version, products)
    references = [
        {"url": x.get("url"), "source": x.get("source"), "tags": list(x.get("tags", []))}
        for x in cve.get("references", [])[:15]
        if x.get("url")
    ]
    return VulnerabilityRecord(
        cve_id=str(cve.get("id", "UNKNOWN")),
        description=extract_description(cve),
        cvss=extract_cvss(cve),
        cwe_ids=extract_cwes(cve),
        affected_products=products,
        references=references,
        published=cve.get("published"),
        last_modified=cve.get("lastModified"),
        vuln_status=cve.get("vulnStatus"),
        applicability=applicability,
        applicability_reason=reason,
    )

class NVDProvider:
    """
    VulnerabilityService가 NVD 내부 구현을 몰라도
    제품·버전 기준으로 취약점 목록을 받을 수 있게 하는 래퍼.
    """

    provider_name = "nvd"

    def __init__(
        self,
        client: NVDClient | None = None,
        minimum_cpe_score: float = 0.55,
        cpe_candidate_limit: int = 10,
    ) -> None:
        self.client = client or NVDClient()
        self.minimum_cpe_score = minimum_cpe_score
        self.cpe_candidate_limit = cpe_candidate_limit

    def search_vulnerabilities(
        self,
        product: str,
        version: str | None,
        vendor: str | None = None,
        cpe: str | None = None,
        max_results: int = 30,
    ) -> list[VulnerabilityRecord]:
        """
        제품·버전 기준으로 NVD 취약점을 조회하고
        VulnerabilityRecord 목록으로 반환한다.
        """

        selected_cpe: str | None = cpe

        # CPE가 입력으로 이미 제공되면 CPE 검색 생략
        if not selected_cpe:
            keyword = " ".join(
                value
                for value in (vendor, product, version)
                if value
            )

            raw_cpes = self.client.search_cpes(
                keyword,
                max_results=self.cpe_candidate_limit,
            )

            service = ServiceInput(
                host=None,
                port=0,
                protocol=None,
                status="open",
                service=product,
                product=product,
                version=version,
                vendor=vendor,
                extra_info=None,
            )

            candidates = normalize_cpe_candidates(
                raw_cpes,
                service,
            )

            selected = select_best_cpe(
                candidates,
                minimum_score=self.minimum_cpe_score,
            )

            if selected:
                selected_cpe = selected.cpe_name

        # CPE가 있으면 CPE 조회
        if selected_cpe:
            raw_vulnerabilities = self.client.search_cves_by_cpe(
                selected_cpe,
                max_results=max_results,
            )

        # CPE가 없으면 키워드 조회
        else:
            keyword = " ".join(
                value
                for value in (product, version)
                if value
            )

            raw_vulnerabilities = self.client.search_cves_by_keyword(
                keyword,
                max_results=max_results,
            )

        return [
            normalize_vulnerability(
                wrapper=item,
                selected_cpe=selected_cpe,
                service_version=version,
            )
            for item in raw_vulnerabilities
        ]