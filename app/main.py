from __future__ import annotations

import asyncio
import contextlib
import csv
import io
import json
import logging
import os
import re
import time
from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime
from pathlib import Path
from typing import Dict, List, Optional
from urllib.parse import parse_qsl, urlsplit, urlunsplit, urlencode
from urllib.parse import quote

import feedparser
import httpx
from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import FileResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from .categorizer import CATEGORY_RULES, categorize_text
from .sources import IA_SOURCE_IDS, SOURCE_REGISTRY, SourceConfig, source_meta


class NewsItem(BaseModel):
    title: str
    link: str
    source_id: str
    source: str
    source_site: str
    source_confidence: str = "media"
    source_relevance: str = "media"
    published_at: datetime
    summary: str
    image_url: Optional[str] = None
    title_ptbr: Optional[str] = None
    summary_ptbr: Optional[str] = None
    category: str
    cves: List[str] = Field(default_factory=list)


class SourcePolicyOverride(BaseModel):
    id: str
    confidence: str
    relevance: str
    profiles: List[str]
    tags: List[str] = Field(default_factory=list)


app = FastAPI(
    title="MADERO INFONEWS",
    description="Coleta notícias de segurança da informação via RSS, categoriza e publica por API.",
    version="1.0.0",
)

BASE_DIR = Path(__file__).resolve().parent
INDEX_HTML = BASE_DIR / "static" / "index.html"
POLICIES_JSON = BASE_DIR / "source_policies.json"


def _env_int(name: str, default: int, minimum: Optional[int] = None, maximum: Optional[int] = None) -> int:
    raw = os.getenv(name)
    if raw is None or raw.strip() == "":
        value = default
    else:
        try:
            value = int(raw)
        except ValueError:
            value = default
    if minimum is not None:
        value = max(minimum, value)
    if maximum is not None:
        value = min(maximum, value)
    return value


def _env_float(name: str, default: float, minimum: Optional[float] = None, maximum: Optional[float] = None) -> float:
    raw = os.getenv(name)
    if raw is None or raw.strip() == "":
        value = default
    else:
        try:
            value = float(raw)
        except ValueError:
            value = default
    if minimum is not None:
        value = max(minimum, value)
    if maximum is not None:
        value = min(maximum, value)
    return value


REFRESH_INTERVAL_SECONDS = _env_int("REFRESH_INTERVAL_SECONDS", 300, minimum=30)
MAX_CACHE_ITEMS = _env_int("MAX_CACHE_ITEMS", 600, minimum=50, maximum=2000)
MAX_ITEMS_PER_SOURCE = _env_int("MAX_ITEMS_PER_SOURCE", 80, minimum=10, maximum=300)
CURATION_WINDOW_DAYS = _env_int("CURATION_WINDOW_DAYS", 7, minimum=1, maximum=30)
CURATION_MIN_ITEMS = _env_int("CURATION_MIN_ITEMS", 5, minimum=1, maximum=100)
CURATION_MIN_RELEVANCE_RATIO = _env_float("CURATION_MIN_RELEVANCE_RATIO", 0.35, minimum=0.0, maximum=1.0)

logger = logging.getLogger("infosec-news-agent")
if not logger.handlers:
    logging.basicConfig(level=logging.INFO)

_cached_news: List[NewsItem] = []
_last_refresh_at: Optional[datetime] = None
_last_refresh_errors: List[str] = []
_refresh_lock = asyncio.Lock()
_refresh_task: Optional[asyncio.Task] = None
CVE_PATTERN = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)
_translation_cache: Dict[str, str] = {}
_source_policy_overrides: Dict[str, dict] = {}
_metrics: Dict[str, object] = {
    "refresh_runs": 0,
    "feeds_total": 0,
    "feeds_ok": 0,
    "feeds_fail": 0,
    "items_ingested": 0,
    "items_deduped": 0,
    "items_cached": 0,
    "dedupe_rate": 0.0,
    "last_refresh_ms": 0,
    "last_refresh_at": None,
    "last_errors": [],
}
OSINT_AREA_KEYWORDS: Dict[str, List[str]] = {
    "username": ["username", "alias", "handle", "whatsmyname", "sherlock"],
    "email": ["email", "mail", "ghunt", "holehe", "hibp"],
    "domain": ["domain", "whois", "dns", "subdomain", "passive dns"],
    "breach": ["breach", "leak", "pwned", "credential", "stealer logs"],
    "geo": ["geolocation", "geo", "maps", "satellite", "imagery"],
    "metadata": ["metadata", "exif", "document properties", "forensics"],
}

app.mount("/static", StaticFiles(directory=BASE_DIR / "static"), name="static")


def _safe_text(value: Optional[str]) -> str:
    return (value or "").strip()


def _is_infosec_relevant(item: NewsItem) -> bool:
    category = (item.category or "").strip().lower()
    if category and category != "geral":
        return True
    blob = f"{item.title} {item.summary}".lower()
    key_terms = [
        "cve-",
        "ransomware",
        "malware",
        "phishing",
        "exploit",
        "vulnerability",
        "threat",
        "siem",
        "soc",
        "edr",
        "xdr",
        "incident response",
    ]
    return any(term in blob for term in key_terms)


def _curated_source_ids(items: List[NewsItem], now: datetime) -> set[str]:
    cutoff = now - timedelta(days=CURATION_WINDOW_DAYS)
    counters: Dict[str, Dict[str, int]] = {}

    for item in items:
        if item.published_at < cutoff:
            continue
        row = counters.setdefault(item.source_id, {"total": 0, "relevant": 0})
        row["total"] += 1
        if _is_infosec_relevant(item):
            row["relevant"] += 1

    muted = set()
    for source_id, row in counters.items():
        total = row["total"]
        if total < CURATION_MIN_ITEMS:
            continue
        ratio = row["relevant"] / max(total, 1)
        if ratio < CURATION_MIN_RELEVANCE_RATIO:
            muted.add(source_id)
    return muted


def _load_source_policy_overrides() -> Dict[str, dict]:
    if not POLICIES_JSON.exists():
        return {}
    try:
        payload = json.loads(POLICIES_JSON.read_text(encoding="utf-8"))
    except Exception:
        return {}
    if not isinstance(payload, dict):
        return {}
    out: Dict[str, dict] = {}
    for source_id, value in payload.items():
        if isinstance(source_id, str) and isinstance(value, dict):
            out[source_id] = value
    return out


def _save_source_policy_overrides(overrides: Dict[str, dict]) -> None:
    POLICIES_JSON.write_text(json.dumps(overrides, ensure_ascii=False, indent=2), encoding="utf-8")


def _effective_source_meta(source_id: str) -> Dict[str, object]:
    base = source_meta(source_id)
    override = _source_policy_overrides.get(source_id, {})
    if not isinstance(override, dict):
        return base
    profiles = override.get("profiles")
    tags = override.get("tags")
    return {
        "confidence": override.get("confidence", base.get("confidence", "media")),
        "relevance": override.get("relevance", base.get("relevance", "media")),
        "profiles": profiles if isinstance(profiles, list) and profiles else base.get("profiles", ["strict", "balanced", "wide"]),
        "tags": tags if isinstance(tags, list) else base.get("tags", []),
    }


def _parse_date(entry: dict) -> datetime:
    date_candidates = [
        entry.get("published"),
        entry.get("updated"),
        entry.get("created"),
    ]

    for candidate in date_candidates:
        if not candidate:
            continue
        try:
            parsed = parsedate_to_datetime(candidate)
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)
            return parsed.astimezone(timezone.utc)
        except (TypeError, ValueError):
            continue

    return datetime.now(timezone.utc)


def _parse_yyyy_mm_dd(value: str) -> datetime:
    try:
        return datetime.strptime(value, "%Y-%m-%d").replace(tzinfo=timezone.utc)
    except ValueError:
        return datetime.now(timezone.utc)


def _extract_cves(text: str) -> List[str]:
    matches = CVE_PATTERN.findall(text or "")
    return sorted({match.upper() for match in matches})


def _normalize_optional_text(value: Optional[str]) -> Optional[str]:
    if not isinstance(value, str):
        return None
    cleaned = value.strip()
    return cleaned or None


def _strip_html(text: str) -> str:
    return re.sub(r"<[^>]+>", " ", text or "")


def _normalize_whitespace(text: str) -> str:
    return re.sub(r"\s+", " ", (text or "")).strip()


def _normalize_link(link: str) -> str:
    raw = (link or "").strip()
    if not raw:
        return ""

    parsed = urlsplit(raw)
    query_pairs = parse_qsl(parsed.query, keep_blank_values=True)
    kept = []
    for key, value in query_pairs:
        lower_key = key.lower()
        if lower_key.startswith("utm_") or lower_key in {
            "fbclid",
            "gclid",
            "mc_cid",
            "mc_eid",
            "oly_anon_id",
            "oly_enc_id",
        }:
            continue
        kept.append((key, value))

    normalized_query = urlencode(kept, doseq=True)
    normalized_path = parsed.path.rstrip("/") or "/"
    return urlunsplit(
        (
            parsed.scheme.lower(),
            parsed.netloc.lower(),
            normalized_path,
            normalized_query,
            "",
        )
    )


def _safe_external_url(url: str) -> str:
    raw = (url or "").strip()
    if not raw:
        return ""
    parsed = urlsplit(raw)
    if parsed.scheme.lower() not in {"http", "https"}:
        return ""
    if not parsed.netloc:
        return ""
    return raw


def _normalize_title(title: str) -> str:
    text = _strip_html(title).lower()
    text = re.sub(r"[^a-z0-9\-\s]", " ", text)
    return _normalize_whitespace(text)


def _content_fingerprint(title: str, summary: str, cves: List[str]) -> str:
    norm_title = _normalize_title(title)
    norm_summary = _normalize_whitespace(_strip_html(summary).lower())
    norm_summary = re.sub(r"[^a-z0-9\-\s]", " ", norm_summary)
    norm_summary = _normalize_whitespace(norm_summary)[:180]
    cve_part = "|".join(sorted({cve.upper() for cve in cves}))
    return f"{norm_title}|{norm_summary}|{cve_part}"


def _extract_image_url(entry: dict, summary: str) -> Optional[str]:
    media_content = entry.get("media_content") or []
    for media in media_content:
        url = _safe_external_url(_safe_text(media.get("url")))
        if url:
            return url

    media_thumbnail = entry.get("media_thumbnail") or []
    for thumb in media_thumbnail:
        url = _safe_external_url(_safe_text(thumb.get("url")))
        if url:
            return url

    links = entry.get("links") or []
    for link in links:
        href = _safe_external_url(_safe_text(link.get("href")))
        link_type = _safe_text(link.get("type")).lower()
        rel = _safe_text(link.get("rel")).lower()
        if href and (link_type.startswith("image/") or rel == "enclosure"):
            return href

    if summary:
        match = re.search(r"<img[^>]+src=[\"']([^\"']+)[\"']", summary, flags=re.IGNORECASE)
        if match:
            return _safe_external_url(_safe_text(match.group(1))) or None

    return None


async def _translate_to_ptbr(
    text: str,
    timeout_seconds: int = 10,
    client: Optional[httpx.AsyncClient] = None,
) -> str:
    normalized = _normalize_whitespace(text)
    if not normalized:
        return normalized
    if normalized in _translation_cache:
        return _translation_cache[normalized]

    url = (
        "https://translate.googleapis.com/translate_a/single?client=gtx"
        f"&sl=auto&tl=pt&dt=t&q={quote(normalized)}"
    )
    headers = {"User-Agent": "Mozilla/5.0"}

    try:
        if client is None:
            async with httpx.AsyncClient(timeout=timeout_seconds, headers=headers) as local_client:
                response = await local_client.get(url)
        else:
            response = await client.get(url)
        response.raise_for_status()
        payload = response.json()
        translated = "".join(chunk[0] for chunk in payload[0] if chunk and chunk[0])
        translated = _normalize_whitespace(translated) or normalized
    except Exception:
        translated = normalized

    _translation_cache[normalized] = translated
    return translated


async def _apply_ptbr_translation(items: List[NewsItem], timeout_seconds: int = 10) -> List[NewsItem]:
    sem = asyncio.Semaphore(6)

    async with httpx.AsyncClient(timeout=timeout_seconds, headers={"User-Agent": "Mozilla/5.0"}) as client:
        async def _translate_item(item: NewsItem) -> NewsItem:
            async with sem:
                title_pt = await _translate_to_ptbr(item.title, timeout_seconds=timeout_seconds, client=client)
                summary_pt = await _translate_to_ptbr(item.summary, timeout_seconds=timeout_seconds, client=client)
                return item.model_copy(
                    update={
                        "title_ptbr": title_pt,
                        "summary_ptbr": summary_pt,
                    }
                )

        return list(await asyncio.gather(*[_translate_item(item) for item in items]))


async def _fetch_source(source: SourceConfig, timeout_seconds: int, client: httpx.AsyncClient) -> List[NewsItem]:
    if not source.feed_url:
        return []

    headers = {
        "User-Agent": "InfoSecNewsAgent/1.0 (+https://localhost)",
        "Accept": "application/rss+xml, application/xml, text/xml;q=0.9, */*;q=0.8",
    }

    response = await client.get(source.feed_url, timeout=timeout_seconds, headers=headers)
    response.raise_for_status()

    if source.feed_type == "json_kev":
        meta = _effective_source_meta(source.id)
        payload = response.json()
        vulnerabilities = payload.get("vulnerabilities", [])
        vulnerabilities = sorted(
            vulnerabilities,
            key=lambda vuln: _safe_text(vuln.get("dateAdded")),
            reverse=True,
        )[:MAX_ITEMS_PER_SOURCE]
        items: List[NewsItem] = []

        for vuln in vulnerabilities:
            cve_id = _safe_text(vuln.get("cveID"))
            if not cve_id:
                continue

            vuln_name = _safe_text(vuln.get("vulnerabilityName"))
            vendor = _safe_text(vuln.get("vendorProject"))
            product = _safe_text(vuln.get("product"))
            summary = _safe_text(vuln.get("shortDescription"))
            note_url = f"https://nvd.nist.gov/vuln/detail/{cve_id}"
            joined = f"{cve_id} {vuln_name} {vendor} {product} {summary}"

            items.append(
                NewsItem(
                    title=f"{cve_id} - {vuln_name or 'Known Exploited Vulnerability'}",
                    link=note_url,
                    source_id=source.id,
                    source=source.name,
                    source_site=source.site_url,
                    source_confidence=str(meta.get("confidence", "media")),
                    source_relevance=str(meta.get("relevance", "media")),
                published_at=_parse_yyyy_mm_dd(_safe_text(vuln.get("dateAdded"))),
                summary=summary,
                image_url=None,
                category=categorize_text(joined),
                cves=[cve_id.upper()],
            )
            )

        return items

    parsed = feedparser.parse(response.text)
    items: List[NewsItem] = []
    meta = _effective_source_meta(source.id)

    for entry in parsed.entries:
        title = _safe_text(entry.get("title"))
        raw_summary = _safe_text(entry.get("summary"))
        summary = raw_summary
        link = _safe_external_url(_safe_text(entry.get("link")))
        if not title or not link:
            continue

        source_name = source.name
        joined = f"{title} {summary}"

        items.append(
            NewsItem(
                title=title,
                link=link,
                source_id=source.id,
                source=source_name,
                source_site=source.site_url,
                source_confidence=str(meta.get("confidence", "media")),
                source_relevance=str(meta.get("relevance", "media")),
                published_at=_parse_date(entry),
                summary=summary,
                image_url=_extract_image_url(entry, raw_summary),
                category=categorize_text(joined),
                cves=_extract_cves(joined),
            )
        )

        if len(items) >= MAX_ITEMS_PER_SOURCE:
            break

    return items


def _dedupe_and_sort(items: List[NewsItem]) -> List[NewsItem]:
    sorted_items = sorted(items, key=lambda item: item.published_at, reverse=True)

    unique_items: List[NewsItem] = []
    seen_links = set()
    seen_titles = set()
    seen_fingerprints = set()

    for item in sorted_items:
        link_key = _normalize_link(item.link)
        title_key = _normalize_title(item.title)
        fingerprint = _content_fingerprint(item.title, item.summary, item.cves)

        if link_key and link_key in seen_links:
            continue
        if title_key and title_key in seen_titles:
            continue
        if fingerprint in seen_fingerprints:
            continue

        if link_key:
            seen_links.add(link_key)
        if title_key:
            seen_titles.add(title_key)
        seen_fingerprints.add(fingerprint)
        unique_items.append(item)

    return unique_items


async def _refresh_news_cache(timeout_seconds: int = 15) -> None:
    global _cached_news, _last_refresh_at, _last_refresh_errors, _metrics

    async with _refresh_lock:
        t0 = time.perf_counter()
        active_sources = [source for source in SOURCE_REGISTRY if source.feed_url]
        async with httpx.AsyncClient(follow_redirects=True) as client:
            tasks = [_fetch_source(source, timeout_seconds=timeout_seconds, client=client) for source in active_sources]
            results = await asyncio.gather(*tasks, return_exceptions=True)

        all_items: List[NewsItem] = []
        errors: List[str] = []

        for source, result in zip(active_sources, results):
            if isinstance(result, Exception):
                errors.append(f"{source.name}: {result.__class__.__name__}")
                continue
            all_items.extend(result)

        sorted_items = _dedupe_and_sort(all_items)
        if sorted_items:
            _cached_news = sorted_items[:MAX_CACHE_ITEMS]

        _last_refresh_at = datetime.now(timezone.utc)
        _last_refresh_errors = errors

        feeds_total = len(active_sources)
        feeds_fail = len(errors)
        feeds_ok = max(0, feeds_total - feeds_fail)
        ingested = len(all_items)
        deduped = max(0, ingested - len(sorted_items))
        dedupe_rate = round((deduped / ingested), 4) if ingested else 0.0
        refresh_ms = int((time.perf_counter() - t0) * 1000)

        _metrics.update(
            {
                "refresh_runs": int(_metrics.get("refresh_runs", 0)) + 1,
                "feeds_total": feeds_total,
                "feeds_ok": feeds_ok,
                "feeds_fail": feeds_fail,
                "items_ingested": ingested,
                "items_deduped": deduped,
                "items_cached": len(_cached_news),
                "dedupe_rate": dedupe_rate,
                "last_refresh_ms": refresh_ms,
                "last_refresh_at": _last_refresh_at,
                "last_errors": errors[:20],
            }
        )
        logger.info(
            json.dumps(
                {
                    "event": "refresh_complete",
                    "feeds_total": feeds_total,
                    "feeds_ok": feeds_ok,
                    "feeds_fail": feeds_fail,
                    "items_ingested": ingested,
                    "items_cached": len(_cached_news),
                    "dedupe_rate": dedupe_rate,
                    "last_refresh_ms": refresh_ms,
                },
                ensure_ascii=False,
            )
        )


async def _refresh_loop() -> None:
    while True:
        try:
            await _refresh_news_cache(timeout_seconds=20)
        except Exception:
            pass
        await asyncio.sleep(REFRESH_INTERVAL_SECONDS)


@app.on_event("startup")
async def startup() -> None:
    global _refresh_task, _source_policy_overrides
    _source_policy_overrides = _load_source_policy_overrides()
    await _refresh_news_cache(timeout_seconds=20)
    _refresh_task = asyncio.create_task(_refresh_loop())


@app.on_event("shutdown")
async def shutdown() -> None:
    global _refresh_task
    if _refresh_task is not None:
        _refresh_task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await _refresh_task
        _refresh_task = None


@app.get("/health")
async def health() -> dict:
    return {
        "status": "ok",
        "service": "infosec-news-agent",
        "last_refresh_at": _last_refresh_at,
        "feeds_ok": _metrics.get("feeds_ok", 0),
        "feeds_total": _metrics.get("feeds_total", 0),
    }


@app.get("/metrics")
async def metrics() -> dict:
    return {
        "service": "infosec-news-agent",
        "refresh": _metrics,
        "last_refresh_errors": _last_refresh_errors,
    }


@app.get("/", include_in_schema=False)
async def home() -> FileResponse:
    return FileResponse(INDEX_HTML)


@app.get("/sources")
async def sources(source_profile: str = Query(default="strict", pattern="^(strict|balanced|wide)$")) -> dict:
    visible_sources = [source for source in SOURCE_REGISTRY if source_profile in _effective_source_meta(source.id).get("profiles", [])]
    return {
        "sources": [
            {
                "id": source.id,
                "name": source.name,
                "site_url": source.site_url,
                "feed_url": source.feed_url,
                "feed_type": source.feed_type,
                "collecting": bool(source.feed_url),
                **_effective_source_meta(source.id),
            }
            for source in visible_sources
        ]
    }


@app.get("/sources/stats")
async def source_stats(source_profile: str = Query(default="strict", pattern="^(strict|balanced|wide)$")) -> dict:
    visible_sources = [source for source in SOURCE_REGISTRY if source_profile in _effective_source_meta(source.id).get("profiles", [])]
    stats: Dict[str, dict] = {
        source.id: {
            "id": source.id,
            "name": source.name,
            "site_url": source.site_url,
            "feed_url": source.feed_url,
            "collecting": bool(source.feed_url),
            "items": 0,
            "last_published_at": None,
            "latest_title": None,
            **_effective_source_meta(source.id),
        }
        for source in visible_sources
    }

    for item in _cached_news:
        if item.source_id in stats:
            row = stats[item.source_id]
            row["items"] += 1
            if row["last_published_at"] is None or item.published_at > row["last_published_at"]:
                row["last_published_at"] = item.published_at
                row["latest_title"] = item.title

    ordered = sorted(stats.values(), key=lambda row: (-row["items"], row["name"]))
    return {
        "last_refresh_at": _last_refresh_at,
        "sources": ordered,
    }


@app.get("/governance/sources")
async def governance_sources() -> dict:
    rows = []
    for source in SOURCE_REGISTRY:
        meta = _effective_source_meta(source.id)
        rows.append(
            {
                "id": source.id,
                "name": source.name,
                "site_url": source.site_url,
                "feed_url": source.feed_url,
                "collecting": bool(source.feed_url),
                **meta,
            }
        )
    rows.sort(key=lambda row: (row["confidence"], row["name"]))
    return {"sources": rows}


@app.get("/governance/policies")
async def governance_policies() -> dict:
    return {
        "policy_file": str(POLICIES_JSON),
        "overrides": _source_policy_overrides,
    }


@app.put("/governance/policies")
async def update_governance_policies(payload: List[SourcePolicyOverride]) -> dict:
    global _source_policy_overrides
    valid_ids = {source.id for source in SOURCE_REGISTRY}
    allowed_profiles = {"strict", "balanced", "wide"}
    allowed_confidence = {"alta", "media", "baixa"}
    allowed_relevance = {"alta", "media", "baixa"}

    overrides: Dict[str, dict] = {}
    for item in payload:
        if item.id not in valid_ids:
            raise HTTPException(status_code=400, detail=f"Fonte invalida: {item.id}")
        profiles = [p.strip() for p in item.profiles if p.strip()]
        if not profiles or any(p not in allowed_profiles for p in profiles):
            raise HTTPException(status_code=400, detail=f"Profiles invalidos para {item.id}")
        confidence = item.confidence.strip().lower()
        relevance = item.relevance.strip().lower()
        if confidence not in allowed_confidence:
            raise HTTPException(status_code=400, detail=f"Confidence invalida para {item.id}")
        if relevance not in allowed_relevance:
            raise HTTPException(status_code=400, detail=f"Relevance invalida para {item.id}")
        tags = sorted({tag.strip().lower() for tag in item.tags if tag.strip()})
        overrides[item.id] = {
            "confidence": confidence,
            "relevance": relevance,
            "profiles": sorted(set(profiles)),
            "tags": tags,
        }

    _save_source_policy_overrides(overrides)
    _source_policy_overrides = overrides
    return {"status": "ok", "saved": len(overrides), "policy_file": str(POLICIES_JSON)}


@app.get("/governance/sources.csv")
async def governance_sources_csv() -> PlainTextResponse:
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(["id", "name", "collecting", "confidence", "relevance", "profiles", "tags", "site_url", "feed_url"])
    for source in SOURCE_REGISTRY:
        meta = _effective_source_meta(source.id)
        writer.writerow(
            [
                source.id,
                source.name,
                "yes" if source.feed_url else "no",
                meta.get("confidence", ""),
                meta.get("relevance", ""),
                ",".join(meta.get("profiles", [])),
                ",".join(meta.get("tags", [])),
                source.site_url,
                source.feed_url or "",
            ]
        )
    return PlainTextResponse(
        content=buffer.getvalue(),
        media_type="text/csv",
        headers={"Content-Disposition": 'attachment; filename="source-governance.csv"'},
    )


@app.get("/categories")
async def categories() -> dict:
    available = sorted({rule.name for rule in CATEGORY_RULES})
    return {"categories": ["Geral", *available]}


@app.get("/cves")
async def cves(limit: int = Query(50, ge=1, le=300)) -> dict:
    counter = {}
    for item in _cached_news:
        for cve in item.cves:
            counter[cve] = counter.get(cve, 0) + 1

    top = sorted(counter.items(), key=lambda pair: (-pair[1], pair[0]))[:limit]
    return {"cves": [{"id": cve, "mentions": mentions} for cve, mentions in top]}


@app.get("/news", response_model=List[NewsItem])
async def news(
    limit: int = Query(20, ge=1, le=200),
    hours: int = Query(72, ge=1, le=720),
    category: Optional[str] = Query(default=None),
    source: Optional[str] = Query(default=None),
    cve: Optional[str] = Query(default=None),
    q: Optional[str] = Query(default=None),
    ptbr: bool = Query(default=False),
    source_profile: str = Query(default="strict", pattern="^(strict|balanced|wide)$"),
    osint_area: Optional[str] = Query(default=None),
    timeout_seconds: int = Query(12, ge=3, le=60),
) -> List[NewsItem]:
    global _cached_news

    now = datetime.now(timezone.utc)
    if _last_refresh_at is None or (now - _last_refresh_at) > timedelta(seconds=REFRESH_INTERVAL_SECONDS + 30):
        await _refresh_news_cache(timeout_seconds=timeout_seconds)

    if not _cached_news:
        detail = "Nenhuma notícia foi coletada das fontes RSS."
        if _last_refresh_errors:
            detail = f"{detail} Falhas: {'; '.join(_last_refresh_errors[:4])}"
        raise HTTPException(status_code=503, detail=detail)

    cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)
    filtered = [item for item in _cached_news if item.published_at >= cutoff]

    if not filtered:
        filtered = list(_cached_news)

    allowed_source_ids = {
        source.id
        for source in SOURCE_REGISTRY
        if source_profile in _effective_source_meta(source.id).get("profiles", [])
    }
    muted_source_ids = _curated_source_ids(_cached_news, now)
    if muted_source_ids:
        allowed_source_ids = {source_id for source_id in allowed_source_ids if source_id not in muted_source_ids}
    filtered = [item for item in filtered if item.source_id in allowed_source_ids]

    normalized_category = _normalize_optional_text(category)
    if normalized_category:
        normalized_category = normalized_category.lower()
        filtered = [item for item in filtered if item.category.lower() == normalized_category]
        if normalized_category == "ia":
            filtered = [item for item in filtered if item.source_id in IA_SOURCE_IDS]

    normalized_source = _normalize_optional_text(source)
    if normalized_source:
        source_tokens = [token.strip().lower() for token in normalized_source.split(",") if token.strip()]
        if not source_tokens:
            source_tokens = []
        if len(source_tokens) > 1:
            allowed = set(source_tokens)
            filtered = [item for item in filtered if item.source_id.lower() in allowed]
        elif len(source_tokens) == 1:
            single = source_tokens[0]
            filtered = [
                item
                for item in filtered
                if item.source_id.lower() == single or single in item.source.lower()
            ]

    normalized_cve = _normalize_optional_text(cve)
    if normalized_cve:
        normalized_cve = normalized_cve.upper()
        filtered = [item for item in filtered if normalized_cve in item.cves]

    normalized_q = _normalize_optional_text(q)
    normalized_osint_area = _normalize_optional_text(osint_area)
    if normalized_osint_area:
        area_key = normalized_osint_area.lower()
        area_terms = OSINT_AREA_KEYWORDS.get(area_key, [])
        if area_terms:
            normalized_q = f"{normalized_q or ''} {' '.join(area_terms)}".strip()
    if normalized_q:
        normalized_q = normalized_q.lower()
        tokens = [token for token in re.split(r"[\s,;|]+", normalized_q) if token]
        if not tokens:
            tokens = [normalized_q]

        def _matches_query(item: NewsItem) -> bool:
            blob = f"{item.title} {item.summary} {item.source}".lower()
            return any(token in blob for token in tokens)

        filtered = [
            item
            for item in filtered
            if _matches_query(item)
        ]

    result = filtered[:limit]
    if ptbr:
        result = await _apply_ptbr_translation(result, timeout_seconds=min(timeout_seconds, 15))
    return result
