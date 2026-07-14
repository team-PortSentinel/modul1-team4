from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass(slots=True)
class ServiceInput:
    """팀 1에서 전달받는 서비스 정보의 팀 2 표준 형식."""

    port: int
    status: str
    service: str
    version: str | None = None
    product: str | None = None
    vendor: str | None = None
    host: str | None = None
    protocol: str = "tcp"
    extra_info: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class CPECandidate:
    cpe_name: str
    title: str
    deprecated: bool = False
    match_score: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class CVSSInfo:
    version: str | None = None
    base_score: float | None = None
    severity: str | None = None
    vector: str | None = None
    source: str | None = None
    metric_type: str | None = None
    attack_vector: str | None = None
    attack_complexity: str | None = None
    privileges_required: str | None = None
    user_interaction: str | None = None
    scope: str | None = None
    confidentiality_impact: str | None = None
    integrity_impact: str | None = None
    availability_impact: str | None = None

    @property
    def missing(self) -> bool:
        return self.base_score is None

    def to_dict(self) -> dict[str, Any]:
        result = asdict(self)
        result["missing"] = self.missing
        return result


@dataclass(slots=True)
class AffectedProduct:
    criteria: str
    vulnerable: bool
    version_start_including: str | None = None
    version_start_excluding: str | None = None
    version_end_including: str | None = None
    version_end_excluding: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class WebEnrichment:
    summary: str | None = None
    affected_versions: list[str] = field(default_factory=list)
    fixed_versions: list[str] = field(default_factory=list)
    mitigation: list[str] = field(default_factory=list)
    known_exploitation: bool | None = None
    sources: list[dict[str, str]] = field(default_factory=list)
    raw_text: str | None = None
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class VulnerabilityRecord:
    cve_id: str
    description: str
    cvss: CVSSInfo
    cwe_ids: list[str] = field(default_factory=list)
    affected_products: list[AffectedProduct] = field(default_factory=list)
    references: list[dict[str, Any]] = field(default_factory=list)
    published: str | None = None
    last_modified: str | None = None
    vuln_status: str | None = None
    applicability: str = "unknown"
    applicability_reason: str = ""
    web: WebEnrichment | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "cve_id": self.cve_id,
            "description": self.description,
            "cvss": self.cvss.to_dict(),
            "cwe_ids": list(self.cwe_ids),
            "affected_products": [item.to_dict() for item in self.affected_products],
            "references": list(self.references),
            "published": self.published,
            "last_modified": self.last_modified,
            "vuln_status": self.vuln_status,
            "applicability": self.applicability,
            "applicability_reason": self.applicability_reason,
            "web": self.web.to_dict() if self.web else None,
        }


@dataclass(slots=True)
class Team3Record:
    cve_id: str
    cvss_score: float | None
    severity: str | None
    attack_vector: str | None
    attack_complexity: str | None
    privileges_required: str | None
    user_interaction: str | None
    cwe: str | None
    description: str
    host: str | None = None
    port: int | None = None
    service: str | None = None
    product: str | None = None
    version: str | None = None
    applicability: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class ServiceAnalysisResult:
    service: ServiceInput
    status: str
    query_method: str
    selected_cpe: CPECandidate | None
    vulnerabilities: list[VulnerabilityRecord]
    warnings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "service": self.service.to_dict(),
            "status": self.status,
            "query_method": self.query_method,
            "selected_cpe": self.selected_cpe.to_dict() if self.selected_cpe else None,
            "vulnerabilities": [item.to_dict() for item in self.vulnerabilities],
            "warnings": list(self.warnings),
        }
