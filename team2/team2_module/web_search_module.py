from __future__ import annotations

import json
import os
from typing import Any

from .schemas import VulnerabilityRecord, WebEnrichment


class WebSearchError(RuntimeError):
    pass


def build_search_prompt(vulnerability: VulnerabilityRecord, product: str | None, version: str | None) -> str:
    return f"""
다음 취약점을 공식 출처 중심으로 웹 검색해 JSON으로 정리해 주세요.
CVE: {vulnerability.cve_id}
제품: {product or '알 수 없음'}
설치 버전: {version or '알 수 없음'}

반환 필드:
- summary: 한 줄 요약
- affected_versions: 영향 버전 배열
- fixed_versions: 수정 버전 배열
- mitigation: 완화/대응 방안 배열
- known_exploitation: 실제 악용 확인 여부(true/false/null)
- sources: title, url, source_type을 가진 배열

출처 우선순위는 벤더 공식 권고문, CISA/NIST/MITRE, 공식 프로젝트 보안 공지 순서입니다.
확인되지 않은 내용은 추측하지 말고 null 또는 빈 배열로 반환하세요.
JSON 객체만 반환하세요.
""".strip()


def _parse_json_text(text: str) -> dict[str, Any]:
    cleaned = text.strip()
    if cleaned.startswith("```"):
        cleaned = cleaned.strip("`")
        if cleaned.lower().startswith("json"):
            cleaned = cleaned[4:].lstrip()
    return json.loads(cleaned)


def enrich_vulnerability_with_web_search(
    vulnerability: VulnerabilityRecord,
    product: str | None,
    version: str | None,
    *,
    client: Any | None = None,
    model: str | None = None,
) -> WebEnrichment:
    """OpenAI Responses API의 web_search 도구로 CVE 정보를 실시간 보강.

    OPENAI_API_KEY는 환경변수로만 읽는다. 호출 실패는 WebEnrichment.error에 기록한다.
    """
    try:
        if client is None:
            from openai import OpenAI

            api_key = os.getenv("OPENAI_API_KEY")
            if not api_key:
                raise WebSearchError("OPENAI_API_KEY 환경변수가 설정되지 않았습니다.")
            client = OpenAI(api_key=api_key)

        response = client.responses.create(
            model=model or os.getenv("OPENAI_MODEL", "gpt-5.5"),
            tools=[{"type": "web_search"}],
            input=build_search_prompt(vulnerability, product, version),
        )
        raw_text = response.output_text
        try:
            data = _parse_json_text(raw_text)
        except (json.JSONDecodeError, TypeError):
            return WebEnrichment(raw_text=raw_text)

        return WebEnrichment(
            summary=data.get("summary"),
            affected_versions=list(data.get("affected_versions") or []),
            fixed_versions=list(data.get("fixed_versions") or []),
            mitigation=list(data.get("mitigation") or []),
            known_exploitation=data.get("known_exploitation"),
            sources=list(data.get("sources") or []),
            raw_text=raw_text,
        )
    except Exception as exc:  # 웹 검색 실패가 전체 NVD 분석을 중단시키지 않도록 함
        return WebEnrichment(error=str(exc))


def enrich_top_vulnerabilities(
    vulnerabilities: list[VulnerabilityRecord],
    product: str | None,
    version: str | None,
    *,
    limit: int = 5,
    client: Any | None = None,
    model: str | None = None,
) -> list[VulnerabilityRecord]:
    """비용·지연을 줄이기 위해 우선순위 상위 CVE만 웹 검색."""
    for vulnerability in vulnerabilities[: max(0, limit)]:
        vulnerability.web = enrich_vulnerability_with_web_search(
            vulnerability,
            product,
            version,
            client=client,
            model=model,
        )
    return vulnerabilities
