import json
import logging
import os
import time
from datetime import datetime, timezone

import pika
import psycopg2
import psycopg2.extras
import requests

from analyzer import CTIAnalyzer

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] [CTI-Worker] %(message)s",
)
logger = logging.getLogger(__name__)


def get_db_connection():
    while True:
        try:
            conn = psycopg2.connect(
                host=os.getenv("POSTGRES_HOST", "postgres"),
                port=os.getenv("POSTGRES_PORT", "5432"),
                user=os.getenv("POSTGRES_USER", "cti_admin"),
                password=os.getenv("POSTGRES_PASSWORD", "cti_secret_pass"),
                dbname=os.getenv("POSTGRES_DB", "cti_radar"),
            )
            conn.autocommit = False
            logger.info("PostgreSQL bağlantısı başarılı.")
            return conn
        except Exception as exc:
            logger.warning(f"PostgreSQL bekleniyor: {exc}")
            time.sleep(3)


def get_rabbitmq_connection():
    user = os.getenv("RABBITMQ_DEFAULT_USER", "cti_broker")
    password = os.getenv("RABBITMQ_DEFAULT_PASS", "cti_broker_pass")
    host = os.getenv("RABBITMQ_HOST", "rabbitmq")
    port = int(os.getenv("RABBITMQ_PORT", "5672"))

    credentials = pika.PlainCredentials(user, password)
    params = pika.ConnectionParameters(
        host=host,
        port=port,
        credentials=credentials,
        heartbeat=60,
        blocked_connection_timeout=300,
    )
    while True:
        try:
            conn = pika.BlockingConnection(params)
            logger.info("RabbitMQ bağlantısı başarılı.")
            return conn
        except Exception as exc:
            logger.warning(f"RabbitMQ bekleniyor: {exc}")
            time.sleep(3)


def fetch_active_watch_rules(db_conn):
    with db_conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute(
            "SELECT id, rule_name, keyword, category, risk_boost, is_active FROM watch_rules WHERE is_active = TRUE"
        )
        return cur.fetchall()


def send_webhook_alert(alert_payload: dict):
    webhook_url = os.getenv("ALERT_WEBHOOK_URL", "").strip()
    if not webhook_url:
        return
    try:
        requests.post(webhook_url, json=alert_payload, timeout=5)
        logger.info("Webhook bildirimi başarıyla gönderildi.")
    except Exception as exc:
        logger.warning(f"Webhook gönderimi başarısız: {exc}")


def process_leak_message(db_conn, analyzer: CTIAnalyzer, payload: dict):
    title = payload.get("title", "Untitled Leak")
    source_type = payload.get("source_type", "unknown")
    source_name = payload.get("source_name", "Unknown Source")
    source_url = payload.get("source_url", "")
    raw_content = payload.get("raw_content", "")
    collected_at = payload.get("collected_at") or datetime.now(timezone.utc).isoformat()

    if not raw_content.strip():
        return

    watch_rules = fetch_active_watch_rules(db_conn)
    analysis = analyzer.analyze(raw_content, title, watch_rules)

    content_hash = analysis["content_hash"]
    new_source_entry = {
        "source_type": source_type,
        "source_name": source_name,
        "source_url": source_url,
        "seen_at": collected_at,
    }

    with db_conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        # 1. Deduplication Kontrolü (SHA-256 Hash)
        cur.execute(
            "SELECT id, seen_sources, occurrence_count, risk_score FROM leaks WHERE content_hash = %s",
            (content_hash,),
        )
        existing = cur.fetchone()

        if existing:
            seen_sources = existing["seen_sources"] or []
            seen_sources.append(new_source_entry)
            new_count = existing["occurrence_count"] + 1
            updated_score = max(existing["risk_score"], analysis["risk_score"])

            cur.execute(
                """
                UPDATE leaks
                SET seen_sources = %s::jsonb,
                    occurrence_count = %s,
                    risk_score = %s,
                     severity = %s,
                    matched_rules = %s::jsonb,
                    last_seen_at = NOW()
                WHERE id = %s
                """,
                (
                    json.dumps(seen_sources),
                    new_count,
                    updated_score,
                    analysis["severity"],
                    json.dumps(analysis["matched_rules"]),
                    existing["id"],
                ),
            )
            db_conn.commit()
            logger.info(
                f"[DEDUP] Tekrarlanan sızıntı güncellendi (ID={existing['id']}, Tekrar={new_count}, Yeni Kaynak={source_name})"
            )
            return

        # 2. Yeni Sızıntı Kaydı
        cur.execute(
            """
            INSERT INTO leaks (
                content_hash, title, source_type, source_name, source_url,
                raw_content, risk_score, severity, extracted_entities,
                matched_rules, seen_sources, occurrence_count
            )
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s::jsonb, %s::jsonb, %s::jsonb, 1)
            RETURNING id
            """,
            (
                content_hash,
                title,
                source_type,
                source_name,
                source_url,
                raw_content,
                analysis["risk_score"],
                analysis["severity"],
                json.dumps(analysis["extracted_entities"]),
                json.dumps(analysis["matched_rules"]),
                json.dumps([new_source_entry]),
            ),
        )
        leak_id = cur.fetchone()["id"]

        # 3. Alarm Üretimi (Watch Rules Eşleşmesi Varsa)
        for rule in analysis["matched_rules"]:
            alert_msg = (
                f"[{analysis['severity']}] '{rule['rule_name']}' kuralı tetiklendi! "
                f"Aranan kelime '{rule['keyword']}', '{source_name}' kaynağındaki '{title}' başlıklı sızıntıda tespit edildi. "
                f"(Risk Skoru: {analysis['risk_score']}/100)"
            )
            cur.execute(
                """
                INSERT INTO alerts (leak_id, rule_name, matched_keyword, severity, message)
                VALUES (%s, %s, %s, %s, %s)
                """,
                (
                    leak_id,
                    rule["rule_name"],
                    rule["keyword"],
                    analysis["severity"],
                    alert_msg,
                ),
            )
            send_webhook_alert(
                {
                    "text": alert_msg,
                    "leak_id": leak_id,
                    "severity": analysis["severity"],
                    "source": source_name,
                }
            )

        db_conn.commit()
        logger.info(
            f"[YENİ SIZINTI] Kaydedildi ID={leak_id} | Başlık='{title}' | Seviye={analysis['severity']} ({analysis['risk_score']}p) | Alarm={len(analysis['matched_rules'])}"
        )


def backfill_existing_leaks(db_conn, analyzer: CTIAnalyzer):
    """Mevcut sızıntı kayıtlarını GeoIP/ASN, Tehdit Aktörü ve Hedef Ülke verileriyle zenginleştirir."""
    try:
        watch_rules = fetch_active_watch_rules(db_conn)
        with db_conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute("SELECT id, title, raw_content, extracted_entities FROM leaks")
            rows = cur.fetchall()
            updated = 0
            for r in rows:
                ent = r["extracted_entities"] or {}
                if "threat_actor" not in ent or "ip_details" not in ent:
                    res = analyzer.analyze(r["raw_content"], r["title"], watch_rules)
                    cur.execute(
                        "UPDATE leaks SET extracted_entities = %s::jsonb WHERE id = %s",
                        (json.dumps(res["extracted_entities"]), r["id"]),
                    )
                    updated += 1
            if updated > 0:
                db_conn.commit()
                logger.info(f"[ENRICHMENT] Mevcut {updated} sızıntı kaydı GeoIP/ASN ve Tehdit Aktörü ile zenginleştirildi.")
    except Exception as exc:
        logger.warning(f"Backfill hatası: {exc}")


def main():
    logger.info("=== Python CTI Analiz, GeoIP Zenginleştirme ve Tekilleştirme Motoru Başlatılıyor ===")
    analyzer = CTIAnalyzer()
    db_conn = get_db_connection()
    backfill_existing_leaks(db_conn, analyzer)

    queue_name = os.getenv("RABBITMQ_QUEUE", "raw_leaks_queue")
    dlq_name = os.getenv("RABBITMQ_DLQ", "raw_leaks_dlq")

    while True:
        try:
            rmq_conn = get_rabbitmq_connection()
            channel = rmq_conn.channel()

            channel.queue_declare(queue=dlq_name, durable=True)
            channel.queue_declare(
                queue=queue_name,
                durable=True,
                arguments={
                    "x-dead-letter-exchange": "",
                    "x-dead-letter-routing-key": dlq_name,
                },
            )
            channel.basic_qos(prefetch_count=5)

            def callback(ch, method, properties, body):
                nonlocal db_conn
                try:
                    if db_conn.closed:
                        db_conn = get_db_connection()
                    payload = json.loads(body.decode("utf-8"))
                    process_leak_message(db_conn, analyzer, payload)
                    ch.basic_ack(delivery_tag=method.delivery_tag)
                except Exception as exc:
                    logger.error(f"Mesaj işleme hatası (DLQ'ya yönlendiriliyor): {exc}")
                    try:
                        db_conn.rollback()
                    except Exception:
                        pass
                    # Hatalı mesajı sonsuz döngüye sokmamak için requeue=False ile DLQ'ya gönder
                    ch.basic_nack(delivery_tag=method.delivery_tag, requeue=False)

            channel.basic_consume(queue=queue_name, on_message_callback=callback)
            logger.info(f"Kuyruk dinleniyor: {queue_name}")
            channel.start_consuming()
        except Exception as exc:
            logger.error(f"Worker bağlantı hatası, 5 sn içinde yeniden bağlanacak: {exc}")
            time.sleep(5)


if __name__ == "__main__":
    main()
