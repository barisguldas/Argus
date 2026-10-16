import csv
import io
import json
import os
import uuid
from datetime import datetime, timezone
from typing import Optional

import pika
import psycopg2
import psycopg2.extras
import requests
from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel

app = FastAPI(
    title="Argus — Enterprise CTI & Data Leak Intelligence API",
    description="Real-Time Dark Web (.onion) Monitoring, GeoIP Enrichment, STIX 2.1 & SOC Case Management Platform",
    version="2.0.0",
)

templates = Jinja2Templates(directory="templates")


def get_db():
    return psycopg2.connect(
        host=os.getenv("POSTGRES_HOST", "postgres"),
        port=os.getenv("POSTGRES_PORT", "5432"),
        user=os.getenv("POSTGRES_USER", "cti_admin"),
        password=os.getenv("POSTGRES_PASSWORD", "cti_secret_pass"),
        dbname=os.getenv("POSTGRES_DB", "cti_radar"),
    )


class WatchRuleCreate(BaseModel):
    rule_name: str
    keyword: str
    category: str = "DOMAIN"
    risk_boost: int = 35


class ManualLeakInject(BaseModel):
    title: str
    source_type: str = "darkweb_forum"
    source_name: str = "Manual SOC Test"
    source_url: str = "http://test-onion-source.onion/paste/1"
    raw_content: str


class ScraperTargetCreate(BaseModel):
    name: str
    url: str
    target_type: str = "darkweb_forum"
    use_tor: bool = True
    interval_seconds: int = 180


class AlertCaseUpdate(BaseModel):
    status: str  # OPEN, INVESTIGATING, RESOLVED, FALSE_POSITIVE
    analyst_note: str = ""


@app.get("/", response_class=HTMLResponse)
def serve_dashboard(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})


@app.get("/api/stats")
def get_dashboard_stats():
    conn = get_db()
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(
                """
                SELECT
                    COUNT(*) AS total_unique_leaks,
                    COALESCE(SUM(occurrence_count - 1), 0) AS deduplicated_hits,
                    COUNT(*) FILTER (WHERE severity = 'CRITICAL') AS critical_count,
                    COUNT(*) FILTER (WHERE severity = 'HIGH') AS high_count,
                    COUNT(*) FILTER (WHERE severity = 'MEDIUM') AS medium_count,
                    COUNT(*) FILTER (WHERE severity = 'LOW') AS low_count,
                    ROUND(COALESCE(AVG(risk_score), 0), 1) AS avg_risk_score
                FROM leaks
                """
            )
            summary = cur.fetchone()

            cur.execute(
                """
                SELECT source_type, COUNT(*) AS count
                FROM leaks
                GROUP BY source_type
                ORDER BY count DESC
                """
            )
            by_source = cur.fetchall()

            # En Aktif Tehdit Aktörleri / Gruplar (Top 6)
            cur.execute(
                """
                SELECT
                    COALESCE(NULLIF(extracted_entities->>'threat_actor', ''), source_name) AS actor,
                    COUNT(*) AS count
                FROM leaks
                GROUP BY actor
                ORDER BY count DESC
                LIMIT 6
                """
            )
            top_actors = cur.fetchall()

            # En Çok Hedef Alınan Ülkeler (Top 6)
            cur.execute(
                """
                SELECT
                    COALESCE(NULLIF(extracted_entities->>'victim_country', ''), 'GLOBAL') AS country,
                    COUNT(*) AS count
                FROM leaks
                GROUP BY country
                ORDER BY count DESC
                LIMIT 6
                """
            )
            top_countries = cur.fetchall()

            cur.execute(
                "SELECT COUNT(*) AS unack_alerts FROM alerts WHERE is_acknowledged = FALSE AND COALESCE(status, 'OPEN') IN ('OPEN', 'INVESTIGATING')"
            )
            unack_alerts = cur.fetchone()["unack_alerts"]

            cur.execute("SELECT COUNT(*) AS active_rules FROM watch_rules WHERE is_active = TRUE")
            active_rules = cur.fetchone()["active_rules"]

            return {
                "summary": summary,
                "by_source": by_source,
                "top_actors": top_actors,
                "top_countries": top_countries,
                "unacknowledged_alerts": unack_alerts,
                "active_rules": active_rules,
            }
    finally:
        conn.close()


@app.get("/api/leaks")
def list_leaks(
    q: Optional[str] = Query(None, description="Tam metin veya IOC araması"),
    severity: Optional[str] = Query(None, description="CRITICAL, HIGH, MEDIUM, LOW"),
    source_type: Optional[str] = Query(None, description="darkweb_forum, paste_site, telegram, threat_feed"),
    limit: int = Query(40, ge=1, le=200),
):
    conn = get_db()
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            conditions = []
            params = []

            if q and q.strip():
                search_term = f"%{q.strip()}%"
                conditions.append(
                    "(title ILIKE %s OR raw_content ILIKE %s OR source_name ILIKE %s OR extracted_entities::text ILIKE %s)"
                )
                params.extend([search_term, search_term, search_term, search_term])

            if severity and severity != "ALL":
                conditions.append("severity = %s")
                params.append(severity.upper())

            if source_type and source_type != "ALL":
                conditions.append("source_type = %s")
                params.append(source_type)

            where_clause = f"WHERE {' AND '.join(conditions)}" if conditions else ""
            query = f"""
                SELECT id, content_hash, title, source_type, source_name, source_url,
                       raw_content, risk_score, severity, extracted_entities,
                       matched_rules, seen_sources, occurrence_count,
                       first_seen_at, last_seen_at
                FROM leaks
                {where_clause}
                ORDER BY last_seen_at DESC
                LIMIT %s
            """
            params.append(limit)
            cur.execute(query, tuple(params))
            return cur.fetchall()
    finally:
        conn.close()


@app.get("/api/leaks/{leak_id}/stix")
def export_leak_stix21(leak_id: int):
    """Seçilen sızıntıyı uluslararası OASIS STIX 2.1 JSON Bundle formatında dışa aktarır."""
    conn = get_db()
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute("SELECT * FROM leaks WHERE id = %s", (leak_id,))
            leak = cur.fetchone()
            if not leak:
                raise HTTPException(status_code=404, detail="Sızıntı bulunamadı")

            now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
            created_iso = leak["first_seen_at"].astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
            ent = leak["extracted_entities"] or {}

            identity_id = "identity--a1b2c3d4-e5f6-4a5b-8c9d-0e1f2a3b4c5d"
            objects = [
                {
                    "type": "identity",
                    "spec_version": "2.1",
                    "id": identity_id,
                    "created": created_iso,
                    "modified": now_iso,
                    "name": "Argus Enterprise CTI & SOC Platform",
                    "identity_class": "organization",
                }
            ]
            object_refs = [identity_id]

            # Threat Actor nesnesi
            actor_name = ent.get("threat_actor") or leak["source_name"]
            actor_id = f"threat-actor--{uuid.uuid5(uuid.NAMESPACE_DNS, actor_name)}"
            objects.append(
                {
                    "type": "threat-actor",
                    "spec_version": "2.1",
                    "id": actor_id,
                    "created": created_iso,
                    "modified": now_iso,
                    "name": actor_name,
                    "threat_actor_types": ["cybercrime", "hacker"],
                }
            )
            object_refs.append(actor_id)

            # IPv4 Indicator nesneleri
            for ip in ent.get("ips", [])[:20]:
                ind_id = f"indicator--{uuid.uuid5(uuid.NAMESPACE_URL, f'ip:{ip}')}"
                objects.append(
                    {
                        "type": "indicator",
                        "spec_version": "2.1",
                        "id": ind_id,
                        "created": created_iso,
                        "modified": now_iso,
                        "name": f"Malicious/Leaked IPv4: {ip}",
                        "pattern": f"[ipv4-addr:value = '{ip}']",
                        "pattern_type": "stix",
                        "valid_from": created_iso,
                        "confidence": leak["risk_score"],
                    }
                )
                object_refs.append(ind_id)

            # Domain Indicator nesneleri
            for dom in ent.get("domains", [])[:20]:
                ind_id = f"indicator--{uuid.uuid5(uuid.NAMESPACE_URL, f'dom:{dom}')}"
                objects.append(
                    {
                        "type": "indicator",
                        "spec_version": "2.1",
                        "id": ind_id,
                        "created": created_iso,
                        "modified": now_iso,
                        "name": f"Leaked/Targeted Domain: {dom}",
                        "pattern": f"[domain-name:value = '{dom}']",
                        "pattern_type": "stix",
                        "valid_from": created_iso,
                        "confidence": leak["risk_score"],
                    }
                )
                object_refs.append(ind_id)

            # CVE Vulnerability nesneleri
            for cve in ent.get("cves", []):
                vuln_id = f"vulnerability--{uuid.uuid5(uuid.NAMESPACE_URL, cve)}"
                objects.append(
                    {
                        "type": "vulnerability",
                        "spec_version": "2.1",
                        "id": vuln_id,
                        "created": created_iso,
                        "modified": now_iso,
                        "name": cve,
                        "external_references": [
                            {"source_name": "cve", "external_id": cve}
                        ],
                    }
                )
                object_refs.append(vuln_id)

            # Ana CTI Report nesnesi
            report_id = f"report--{uuid.uuid5(uuid.NAMESPACE_URL, leak['content_hash'])}"
            objects.append(
                {
                    "type": "report",
                    "spec_version": "2.1",
                    "id": report_id,
                    "created": created_iso,
                    "modified": now_iso,
                    "name": leak["title"],
                    "description": leak["raw_content"][:2000],
                    "published": now_iso,
                    "report_types": ["threat-report", "attack-pattern"],
                    "object_refs": object_refs,
                    "confidence": leak["risk_score"],
                    "labels": [leak["severity"].lower(), leak["source_type"]],
                }
            )

            bundle = {
                "type": "bundle",
                "id": f"bundle--{uuid.uuid4()}",
                "objects": objects,
            }

            headers = {
                "Content-Disposition": f'attachment; filename="argus-stix21-leak-{leak_id}.json"'
            }
            return JSONResponse(content=bundle, headers=headers)
    finally:
        conn.close()


@app.get("/api/leaks/{leak_id}/report", response_class=HTMLResponse)
def generate_incident_report_html(leak_id: int, lang: str = Query("tr")):
    """Üst yönetim ve SOC ekipleri için TR/EN çok dilli, yazdırılabilir (PDF destekli) TLP:AMBER Olay Raporu üretir."""
    is_en = lang.lower() == "en"
    conn = get_db()
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute("SELECT * FROM leaks WHERE id = %s", (leak_id,))
            leak = cur.fetchone()
            if not leak:
                raise HTTPException(status_code=404, detail="Leak not found")

            ent = leak["extracted_entities"] or {}
            rules = leak["matched_rules"] or []
            none_txt = "None detected" if is_en else "Tespit edilmedi"

            ips_html = "".join(
                f"<li><code>{d['ip']}</code> — <b>{d['country']}</b> ({d['isp']} {d['asn']})</li>"
                for d in ent.get("ip_details", [])
            ) or f"<li>{none_txt}</li>"

            domains_html = "".join(f"<li><code>{dom}</code></li>" for dom in ent.get("domains", [])) or f"<li>{none_txt}</li>"
            creds_html = "".join(f"<li><code>{c}</code></li>" for c in ent.get("credentials", [])) or f"<li>{none_txt}</li>"
            cves_html = "".join(f"<li><code>{c}</code></li>" for c in ent.get("cves", [])) or f"<li>{none_txt}</li>"
            rules_html = "".join(
                f"<li><b>{r['rule_name']}</b> (Keyword: <code>{r['keyword']}</code>, +{r['risk_boost']}p)</li>"
                for r in rules
            ) or f"<li>{'No custom rules matched' if is_en else 'Eşleşen özel kural yok'}</li>"

            lbl = {
                "doc_title": f"Argus SOC Incident Report #{leak['id']}" if is_en else f"Argus SOC Olay Raporu #{leak['id']}",
                "print_btn": "Print / Save as PDF" if is_en else "PDF Olarak Yazdır / Kaydet",
                "subtitle": "ARGUS ENTERPRISE CTI — SOC INCIDENT REPORT",
                "incident": "Incident" if is_en else "Olay",
                "tlp": "TLP:AMBER (RESTRICTED)" if is_en else "TLP:AMBER (KISITLI PAYLAŞIM)",
                "sev": "Severity & Risk Score" if is_en else "Tehdit Seviyesi & Skoru",
                "actor": "Threat Actor / Group" if is_en else "Tehdit Aktörü / Grup",
                "country": "Target Country / Region" if is_en else "Hedef Ülke / Bölge",
                "source": "Source Name & Type" if is_en else "Kaynak Adı & Tipi",
                "url": "Source URL (.onion / Feed)" if is_en else "Kaynak URL (.onion / Feed)",
                "hash": "SHA-256 Deduplication Hash" if is_en else "SHA-256 Tekilleştirme Özeti",
                "occ": "Seen Count" if is_en else "Görüldüğü Kaynak Sayısı",
                "time": "First / Last Seen Timestamp" if is_en else "İlk / Son Görülme Zamanı",
                "sec1": "1. Triggered Enterprise Watch Rules" if is_en else "1. Tetiklenen Kurumsal SOC Kuralları",
                "sec2": "2. Extracted IOCs & Enriched Intelligence" if is_en else "2. Çıkarılan IOC ve Zenginleştirilmiş İstihbarat Bulguları",
                "ip_lbl": "Enriched IPv4 (GeoIP & ASN)" if is_en else "Zenginleştirilmiş IPv4 (GeoIP & ASN)",
                "dom_lbl": "Detected Domains" if is_en else "Tespit Edilen Alan Adları (Domains)",
                "cred_lbl": "Exposed Credentials" if is_en else "İfşa Olan Kimlik Bilgileri (Credentials)",
                "cve_lbl": "Associated Vulnerabilities (CVEs)" if is_en else "İlgili Zafiyetler (CVEs)",
                "sec3": "3. Raw Leak Evidence" if is_en else "3. Ham Sızıntı Kanıt Metni (Raw Evidence)",
            }

            html_doc = f"""<!DOCTYPE html>
<html lang="{'en' if is_en else 'tr'}">
<head>
    <meta charset="UTF-8">
    <title>{lbl['doc_title']} - {leak['title']}</title>
    <style>
        body {{ font-family: 'Segoe UI', Arial, sans-serif; background: #f8fafc; color: #0f172a; margin: 0; padding: 32px; }}
        .page {{ max-width: 900px; margin: 0 auto; background: #fff; border: 1px solid #cbd5e1; border-radius: 8px; padding: 36px; box-shadow: 0 4px 20px rgba(0,0,0,0.06); }}
        .header {{ display: flex; justify-content: space-between; align-items: center; border-bottom: 2px solid #0f172a; padding-bottom: 16px; margin-bottom: 24px; }}
        .tlp {{ background: #f59e0b; color: #000; font-weight: 800; padding: 4px 12px; border-radius: 4px; font-size: 12px; letter-spacing: 1px; }}
        .badge {{ display: inline-block; padding: 6px 14px; border-radius: 6px; font-weight: bold; font-size: 14px; background: #fee2e2; color: #991b1b; }}
        table {{ width: 100%; border-collapse: collapse; margin-bottom: 24px; font-size: 14px; }}
        th, td {{ border: 1px solid #e2e8f0; padding: 10px 12px; text-align: left; }}
        th {{ background: #f1f5f9; width: 230px; color: #334155; }}
        h2 {{ font-size: 16px; text-transform: uppercase; color: #1e293b; border-left: 4px solid #0284c7; padding-left: 10px; margin-top: 28px; }}
        pre {{ background: #0f172a; color: #e2e8f0; padding: 16px; border-radius: 6px; white-space: pre-wrap; word-break: break-all; font-size: 12px; }}
        .print-btn {{ background: #0284c7; color: #fff; border: none; padding: 10px 18px; border-radius: 6px; cursor: pointer; font-weight: bold; }}
        @media print {{ .no-print {{ display: none; }} body {{ background: #fff; padding: 0; }} .page {{ box-shadow: none; border: none; }} }}
    </style>
</head>
<body>
    <div class="page">
        <div class="no-print" style="margin-bottom: 20px; text-align: right;">
            <button class="print-btn" onclick="window.print()">{lbl['print_btn']}</button>
        </div>
        <div class="header">
            <div>
                <div style="font-size: 12px; color: #64748b; font-weight: bold;">{lbl['subtitle']}</div>
                <h1 style="margin: 6px 0 0 0; font-size: 22px;">{lbl['incident']} #{leak['id']}: {leak['title']}</h1>
            </div>
            <span class="tlp">{lbl['tlp']}</span>
        </div>

        <table>
            <tr><th>{lbl['sev']}</th><td><span class="badge">{leak['severity']} ({leak['risk_score']}/100)</span></td></tr>
            <tr><th>{lbl['actor']}</th><td><b>{ent.get('threat_actor', 'Unknown')}</b></td></tr>
            <tr><th>{lbl['country']}</th><td><b>{ent.get('victim_country', 'GLOBAL')}</b></td></tr>
            <tr><th>{lbl['source']}</th><td>{leak['source_name']} (<code>{leak['source_type']}</code>)</td></tr>
            <tr><th>{lbl['url']}</th><td><code>{leak['source_url']}</code></td></tr>
            <tr><th>{lbl['hash']}</th><td><code>{leak['content_hash']}</code> ({lbl['occ']}: {leak['occurrence_count']})</td></tr>
            <tr><th>{lbl['time']}</th><td>{leak['first_seen_at']} / {leak['last_seen_at']}</td></tr>
        </table>

        <h2>{lbl['sec1']}</h2>
        <ul>{rules_html}</ul>

        <h2>{lbl['sec2']}</h2>
        <table>
            <tr><th>{lbl['ip_lbl']}</th><td><ul>{ips_html}</ul></td></tr>
            <tr><th>{lbl['dom_lbl']}</th><td><ul>{domains_html}</ul></td></tr>
            <tr><th>{lbl['cred_lbl']}</th><td><ul>{creds_html}</ul></td></tr>
            <tr><th>{lbl['cve_lbl']}</th><td><ul>{cves_html}</ul></td></tr>
        </table>

        <h2>{lbl['sec3']}</h2>
        <pre>{leak['raw_content']}</pre>
    </div>
</body>
</html>"""
            return HTMLResponse(content=html_doc)
    finally:
        conn.close()


@app.get("/api/export/csv")
def export_all_leaks_csv():
    """Tüm sızıntıları SIEM ve Excel analizi için CSV formatında dışa aktarır."""
    conn = get_db()
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(
                """
                SELECT id, title, severity, risk_score, source_type, source_name,
                       source_url, content_hash, occurrence_count, last_seen_at,
                       extracted_entities
                FROM leaks
                ORDER BY last_seen_at DESC
                LIMIT 500
                """
            )
            rows = cur.fetchall()

            output = io.StringIO()
            output.write("\ufeff")  # Excel Türkçe karakter uyumu için UTF-8 BOM
            writer = csv.writer(output)
            writer.writerow(
                [
                    "ID",
                    "Baslik",
                    "Seviye",
                    "Risk_Skoru",
                    "Tehdit_Aktoru",
                    "Hedef_Ulke",
                    "Kaynak_Tipi",
                    "Kaynak_Adi",
                    "Kaynak_URL",
                    "IP_Adresleri",
                    "Domainler",
                    "CVE_Listesi",
                    "Tekrar_Sayisi",
                    "SHA256",
                    "Son_Gorulme",
                ]
            )
            for r in rows:
                ent = r["extracted_entities"] or {}
                writer.writerow(
                    [
                        r["id"],
                        r["title"],
                        r["severity"],
                        r["risk_score"],
                        ent.get("threat_actor", ""),
                        ent.get("victim_country", ""),
                        r["source_type"],
                        r["source_name"],
                        r["source_url"],
                        "; ".join(ent.get("ips", [])),
                        "; ".join(ent.get("domains", [])),
                        "; ".join(ent.get("cves", [])),
                        r["occurrence_count"],
                        r["content_hash"],
                        r["last_seen_at"].isoformat() if r["last_seen_at"] else "",
                    ]
                )

            output.seek(0)
            headers = {
                "Content-Disposition": 'attachment; filename="cti_leaks_export.csv"'
            }
            return StreamingResponse(
                iter([output.getvalue()]),
                media_type="text/csv; charset=utf-8",
                headers=headers,
            )
    finally:
        conn.close()


@app.get("/api/alerts")
def list_alerts(limit: int = 35):
    conn = get_db()
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(
                """
                SELECT a.id, a.leak_id, a.rule_name, a.matched_keyword,
                       a.severity, a.message, a.is_acknowledged,
                       COALESCE(a.status, 'OPEN') AS status,
                       COALESCE(a.analyst_note, '') AS analyst_note,
                       a.created_at,
                       l.title AS leak_title, l.source_name
                FROM alerts a
                LEFT JOIN leaks l ON l.id = a.leak_id
                ORDER BY
                    CASE WHEN COALESCE(a.status, 'OPEN') IN ('OPEN', 'INVESTIGATING') THEN 0 ELSE 1 END ASC,
                    a.created_at DESC
                LIMIT %s
                """,
                (limit,),
            )
            return cur.fetchall()
    finally:
        conn.close()


@app.post("/api/alerts/{alert_id}/case")
def update_alert_case(alert_id: int, update: AlertCaseUpdate):
    """SOC Olay Yönetimi (Case Management): Alarmın durumunu ve analist notunu günceller."""
    conn = get_db()
    try:
        is_ack = update.status in ("RESOLVED", "FALSE_POSITIVE")
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE alerts
                SET status = %s,
                    analyst_note = %s,
                    is_acknowledged = %s
                WHERE id = %s
                """,
                (update.status, update.analyst_note.strip(), is_ack, alert_id),
            )
            conn.commit()
            return {"status": "updated", "id": alert_id, "case_status": update.status}
    finally:
        conn.close()


@app.post("/api/alerts/{alert_id}/ack")
def acknowledge_alert(alert_id: int):
    conn = get_db()
    try:
        with conn.cursor() as cur:
            cur.execute(
                "UPDATE alerts SET is_acknowledged = TRUE, status = 'RESOLVED' WHERE id = %s",
                (alert_id,),
            )
            conn.commit()
            return {"status": "ok", "acknowledged_id": alert_id}
    finally:
        conn.close()


@app.get("/api/rules")
def list_watch_rules():
    conn = get_db()
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute("SELECT * FROM watch_rules ORDER BY created_at DESC")
            return cur.fetchall()
    finally:
        conn.close()


@app.post("/api/rules")
def create_watch_rule(rule: WatchRuleCreate):
    conn = get_db()
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(
                """
                INSERT INTO watch_rules (rule_name, keyword, category, risk_boost)
                VALUES (%s, %s, %s, %s)
                ON CONFLICT (keyword) DO UPDATE
                SET rule_name = EXCLUDED.rule_name,
                    category = EXCLUDED.category,
                    risk_boost = EXCLUDED.risk_boost,
                    is_active = TRUE
                RETURNING *
                """,
                (rule.rule_name.strip(), rule.keyword.strip(), rule.category, rule.risk_boost),
            )
            created = cur.fetchone()
            conn.commit()
            return created
    finally:
        conn.close()


@app.delete("/api/rules/{rule_id}")
def delete_watch_rule(rule_id: int):
    conn = get_db()
    try:
        with conn.cursor() as cur:
            cur.execute("DELETE FROM watch_rules WHERE id = %s", (rule_id,))
            conn.commit()
            return {"status": "deleted", "id": rule_id}
    finally:
        conn.close()


@app.get("/api/targets")
def list_scraper_targets():
    conn = get_db()
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute("SELECT * FROM scraper_targets ORDER BY created_at DESC")
            return cur.fetchall()
    finally:
        conn.close()


@app.post("/api/targets")
def create_scraper_target(target: ScraperTargetCreate):
    conn = get_db()
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(
                """
                INSERT INTO scraper_targets (name, url, target_type, use_tor, interval_seconds, last_scraped_at, last_status)
                VALUES (%s, %s, %s, %s, %s, NULL, 'QUEUED')
                RETURNING *
                """,
                (target.name.strip(), target.url.strip(), target.target_type, target.use_tor, target.interval_seconds),
            )
            row = cur.fetchone()
            conn.commit()
            return row
    finally:
        conn.close()


@app.post("/api/targets/{target_id}/scan")
def trigger_target_scan_now(target_id: int):
    conn = get_db()
    try:
        with conn.cursor() as cur:
            cur.execute(
                "UPDATE scraper_targets SET last_scraped_at = NULL, last_status = 'QUEUED' WHERE id = %s",
                (target_id,),
            )
            conn.commit()
            return {"status": "triggered", "id": target_id}
    finally:
        conn.close()


@app.delete("/api/targets/{target_id}")
def delete_scraper_target(target_id: int):
    conn = get_db()
    try:
        with conn.cursor() as cur:
            cur.execute("DELETE FROM scraper_targets WHERE id = %s", (target_id,))
            conn.commit()
            return {"status": "deleted", "id": target_id}
    finally:
        conn.close()


@app.post("/api/inject")
def inject_raw_leak_to_queue(item: ManualLeakInject):
    user = os.getenv("RABBITMQ_DEFAULT_USER", "cti_broker")
    password = os.getenv("RABBITMQ_DEFAULT_PASS", "cti_broker_pass")
    host = os.getenv("RABBITMQ_HOST", "rabbitmq")
    port = int(os.getenv("RABBITMQ_PORT", "5672"))
    queue_name = os.getenv("RABBITMQ_QUEUE", "raw_leaks_queue")
    dlq_name = os.getenv("RABBITMQ_DLQ", "raw_leaks_dlq")

    try:
        credentials = pika.PlainCredentials(user, password)
        conn = pika.BlockingConnection(
            pika.ConnectionParameters(host=host, port=port, credentials=credentials)
        )
        ch = conn.channel()
        ch.queue_declare(queue=dlq_name, durable=True)
        ch.queue_declare(
            queue=queue_name,
            durable=True,
            arguments={
                "x-dead-letter-exchange": "",
                "x-dead-letter-routing-key": dlq_name,
            },
        )
        event = {
            "title": item.title,
            "source_type": item.source_type,
            "source_name": item.source_name,
            "source_url": item.source_url,
            "raw_content": item.raw_content,
            "collected_at": datetime.now(timezone.utc).isoformat(),
        }
        ch.basic_publish(
            exchange="",
            routing_key=queue_name,
            body=json.dumps(event).encode("utf-8"),
            properties=pika.BasicProperties(
                delivery_mode=2, content_type="application/json"
            ),
        )
        conn.close()
        return {"status": "queued", "queue": queue_name}
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"RabbitMQ hatası: {exc}")


@app.get("/api/tor-check")
def check_tor_proxy_status():
    proxy_addr = os.getenv("TOR_PROXY_ADDR", "haproxy-tor:9050")
    proxies = {
        "http": f"socks5h://{proxy_addr}",
        "https": f"socks5h://{proxy_addr}",
    }
    try:
        resp = requests.get(
            "https://check.torproject.org/api/ip", proxies=proxies, timeout=12
        )
        data = resp.json()
        return {
            "connected": True,
            "is_tor": data.get("IsTor", False),
            "exit_ip": data.get("IP", "Unknown"),
            "proxy": proxy_addr,
        }
    except Exception as exc:
        return {
            "connected": False,
            "is_tor": False,
            "exit_ip": None,
            "proxy": proxy_addr,
            "error": str(exc),
        }
