from __future__ import annotations

from dataclasses import replace
from typing import Literal

from .nvd_module import (
    NVDClientError,
    NVDProvider,
    normalize_vulnerability as normalize_nvd_vulnerability,
)
from .schemas import CVSSInfo, VulnerabilityRecord
from .vulners_module import VulnersClientError, VulnersProvider

ProviderOrder = Literal["vulners", "nvd"]


class HybridVulnerabilityProvider:
    """
    Vulners와 NVD를 함께 사용하는 하이브리드 공급자.

    기본값은 실시간 속도를 위해 Vulners 우선이다.
    - Vulners 우선: 후보를 빠르게 수집하고 상위 CVE만 NVD 단건 조회로 검증
    - NVD 우선: NVD 결과가 없거나 필드가 부족할 때 Vulners로 보완

    Web Search는 이 공급자가 아니라 vulnerability_service.py에서
    병합 완료 후 상위 CVE에만 수행한다.
    """

    provider_name = "hybrid"

    def __init__(
        self,
        nvd_provider: NVDProvider | None = None,
        vulners_provider: VulnersProvider | None = None,
        *,
        primary: ProviderOrder = "vulners",
        nvd_verify_limit: int = 3,
        include_secondary_only_records: bool = True,
    ) -> None:
        if primary not in {"vulners", "nvd"}:
            raise ValueError("primary는 'vulners' 또는 'nvd'여야 합니다.")
        if nvd_verify_limit < 0:
            raise ValueError("nvd_verify_limit은 0 이상이어야 합니다.")

        self.nvd_provider = nvd_provider or NVDProvider()
        self.vulners_provider = vulners_provider or VulnersProvider()
        self.primary = primary
        self.nvd_verify_limit = nvd_verify_limit
        self.include_secondary_only_records = include_secondary_only_records
        self.last_warnings: list[str] = []
        self.last_sources: list[str] = []

    def search_vulnerabilities(
        self,
        product: str,
        version: str | None,
        vendor: str | None = None,
        cpe: str | None = None,
        max_results: int = 30,
    ) -> list[VulnerabilityRecord]:
        self.last_warnings = []
        self.last_sources = []

        if self.primary == "nvd":
            records = self._search_nvd_first(
                product=product,
                version=version,
                vendor=vendor,
                cpe=cpe,
                max_results=max_results,
            )
        else:
            records = self._search_vulners_first(
                product=product,
                version=version,
                vendor=vendor,
                cpe=cpe,
                max_results=max_results,
            )

        return _sort_records(records)[:max_results]

    def _search_nvd_first(
        self,
        *,
        product: str,
        version: str | None,
        vendor: str | None,
        cpe: str | None,
        max_results: int,
    ) -> list[VulnerabilityRecord]:
        nvd_records: list[VulnerabilityRecord] = []

        try:
            nvd_records = self.nvd_provider.search_vulnerabilities(
                product=product,
                version=version,
                vendor=vendor,
                cpe=cpe,
                max_results=max_results,
            )
            self.last_sources.append("nvd")
        except (NVDClientError, ValueError) as exc:
            self.last_warnings.append(f"NVD 조회 실패: {exc}")

        # NVD 결과가 충분하면 추가 API 호출을 하지 않는다.
        if nvd_records and not any(_record_is_incomplete(x) for x in nvd_records):
            return nvd_records

        try:
            vulners_records = self.vulners_provider.search_vulnerabilities(
                product=product,
                version=version,
                vendor=vendor,
                cpe=cpe,
                max_results=max_results,
            )
            self.last_sources.append("vulners")
        except (VulnersClientError, ValueError) as exc:
            self.last_warnings.append(f"Vulners 보완 조회 실패: {exc}")
            return nvd_records

        if not nvd_records:
            return vulners_records

        return merge_vulnerability_records(
            primary_records=nvd_records,
            secondary_records=vulners_records,
            include_secondary_only=self.include_secondary_only_records,
        )

    def _search_vulners_first(
        self,
        *,
        product: str,
        version: str | None,
        vendor: str | None,
        cpe: str | None,
        max_results: int,
    ) -> list[VulnerabilityRecord]:
        vulners_records: list[VulnerabilityRecord] = []

        try:
            vulners_records = self.vulners_provider.search_vulnerabilities(
                product=product,
                version=version,
                vendor=vendor,
                cpe=cpe,
                max_results=max_results,
            )
            self.last_sources.append("vulners")
        except (VulnersClientError, ValueError) as exc:
            self.last_warnings.append(f"Vulners 조회 실패: {exc}")

        # Vulners 자체가 실패하거나 결과가 없으면 NVD 전체 조회로 대체한다.
        if not vulners_records:
            try:
                nvd_records = self.nvd_provider.search_vulnerabilities(
                    product=product,
                    version=version,
                    vendor=vendor,
                    cpe=cpe,
                    max_results=max_results,
                )
                self.last_sources.append("nvd")
                return nvd_records
            except (NVDClientError, ValueError) as exc:
                self.last_warnings.append(f"NVD 대체 조회 실패: {exc}")
                return []

        # 상위 CVE만 NVD 단건 조회하여 공식 데이터로 보완한다.
        verify_targets = _sort_records(vulners_records)[: self.nvd_verify_limit]
        nvd_records: list[VulnerabilityRecord] = []

        for record in verify_targets:
            try:
                wrapper = self.nvd_provider.client.get_cve(record.cve_id)
            except NVDClientError as exc:
                self.last_warnings.append(
                    f"{record.cve_id} NVD 검증 실패: {exc}"
                )
                # 429 등 연속 실패 시 나머지 검증을 중단해 지연을 줄인다.
                break

            if not wrapper:
                continue

            nvd_records.append(
                normalize_nvd_vulnerability(
                    wrapper=wrapper,
                    selected_cpe=cpe,
                    service_version=version,
                )
            )

        if nvd_records:
            self.last_sources.append("nvd")

        return merge_vulnerability_records(
            primary_records=vulners_records,
            secondary_records=nvd_records,
            include_secondary_only=False,
            prefer_secondary_official=True,
        )


def _record_is_incomplete(record: VulnerabilityRecord) -> bool:
    return any(
        (
            record.cvss.base_score is None,
            not record.cwe_ids,
            not record.description,
            record.description == "설명 없음",
        )
    )


def merge_vulnerability_records(
    primary_records: list[VulnerabilityRecord],
    secondary_records: list[VulnerabilityRecord],
    *,
    include_secondary_only: bool = True,
    prefer_secondary_official: bool = False,
) -> list[VulnerabilityRecord]:
    """CVE ID 기준으로 두 공급자의 결과를 병합한다."""
    primary_map = {record.cve_id: record for record in primary_records}
    secondary_map = {record.cve_id: record for record in secondary_records}

    merged: list[VulnerabilityRecord] = []
    all_ids = list(primary_map)

    if include_secondary_only:
        all_ids.extend(
            cve_id for cve_id in secondary_map if cve_id not in primary_map
        )

    for cve_id in all_ids:
        primary = primary_map.get(cve_id)
        secondary = secondary_map.get(cve_id)

        if primary and secondary:
            merged.append(
                _merge_single_record(
                    primary,
                    secondary,
                    prefer_secondary_official=prefer_secondary_official,
                )
            )
        elif primary:
            merged.append(primary)
        elif secondary:
            merged.append(secondary)

    return _sort_records(merged)


def _merge_single_record(
    primary: VulnerabilityRecord,
    secondary: VulnerabilityRecord,
    *,
    prefer_secondary_official: bool,
) -> VulnerabilityRecord:
    """기본 공급자 값을 유지하되 비어 있는 필드를 보완한다."""
    if prefer_secondary_official and secondary.cvss.base_score is not None:
        cvss = _merge_cvss(secondary.cvss, primary.cvss)
    else:
        cvss = _merge_cvss(primary.cvss, secondary.cvss)

    description = primary.description
    if not description or description == "설명 없음":
        description = secondary.description

    # CWE는 양쪽 결과를 합쳐 정보 손실을 줄인다.
    cwe_ids = sorted(set(primary.cwe_ids) | set(secondary.cwe_ids))

    # NVD에서 얻은 영향 제품/적용 판정이 있으면 우선 보존한다.
    if secondary.affected_products and not primary.affected_products:
        affected_products = secondary.affected_products
    else:
        affected_products = primary.affected_products

    applicability = primary.applicability
    applicability_reason = primary.applicability_reason
    if secondary.applicability in {"affected", "not_affected", "needs_review"}:
        if primary.applicability == "unknown" or prefer_secondary_official:
            applicability = secondary.applicability
            applicability_reason = secondary.applicability_reason

    return replace(
        primary,
        description=description,
        cvss=cvss,
        cwe_ids=cwe_ids,
        affected_products=affected_products,
        references=_merge_references(primary.references, secondary.references),
        published=primary.published or secondary.published,
        last_modified=primary.last_modified or secondary.last_modified,
        vuln_status=primary.vuln_status or secondary.vuln_status,
        applicability=applicability,
        applicability_reason=applicability_reason,
    )


def _merge_cvss(primary: CVSSInfo, secondary: CVSSInfo) -> CVSSInfo:
    """CVSS 객체의 비어 있는 세부 필드를 보완한다."""
    return CVSSInfo(
        version=primary.version or secondary.version,
        base_score=(
            primary.base_score
            if primary.base_score is not None
            else secondary.base_score
        ),
        severity=primary.severity or secondary.severity,
        vector=primary.vector or secondary.vector,
        source=primary.source or secondary.source,
        metric_type=primary.metric_type or secondary.metric_type,
        attack_vector=primary.attack_vector or secondary.attack_vector,
        attack_complexity=(
            primary.attack_complexity or secondary.attack_complexity
        ),
        privileges_required=(
            primary.privileges_required or secondary.privileges_required
        ),
        user_interaction=(
            primary.user_interaction or secondary.user_interaction
        ),
        scope=primary.scope or secondary.scope,
        confidentiality_impact=(
            primary.confidentiality_impact or secondary.confidentiality_impact
        ),
        integrity_impact=(
            primary.integrity_impact or secondary.integrity_impact
        ),
        availability_impact=(
            primary.availability_impact or secondary.availability_impact
        ),
    )


def _merge_references(
    first: list[dict],
    second: list[dict],
    limit: int = 20,
) -> list[dict]:
    result: list[dict] = []
    seen: set[str] = set()

    for item in [*first, *second]:
        url = item.get("url") if isinstance(item, dict) else None
        if not url or url in seen:
            continue
        seen.add(url)
        result.append(item)
        if len(result) >= limit:
            break

    return result


def _sort_records(
    records: list[VulnerabilityRecord],
) -> list[VulnerabilityRecord]:
    unique: dict[str, VulnerabilityRecord] = {}
    for record in records:
        unique[record.cve_id] = record

    priority = {"affected": 0, "needs_review": 1, "unknown": 2}
    return sorted(
        unique.values(),
        key=lambda record: (
            priority.get(record.applicability, 9),
            -(
                record.cvss.base_score
                if record.cvss.base_score is not None
                else -1.0
            ),
            record.cve_id,
        ),
    )
