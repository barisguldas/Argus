-- CTI & Veri Sızıntısı Radarı Veritabanı Şeması
SET client_encoding = 'UTF8';

CREATE EXTENSION IF NOT EXISTS pg_trgm;

-- 1. İşlenmiş Veri Sızıntıları Tablosu (Deduplication + JSONB IOCs)
CREATE TABLE IF NOT EXISTS leaks (
    id SERIAL PRIMARY KEY,
    content_hash VARCHAR(64) UNIQUE NOT NULL,          -- SHA-256 Tekilleştirme Anahtarı
    title VARCHAR(500) NOT NULL,
    source_type VARCHAR(50) NOT NULL,                  -- darkweb_forum, paste_site, telegram, threat_feed
    source_name VARCHAR(255) NOT NULL,
    source_url TEXT,
    raw_content TEXT NOT NULL,
    risk_score INTEGER NOT NULL DEFAULT 0,             -- 0 - 100 arası dinamik risk skoru
    severity VARCHAR(20) NOT NULL DEFAULT 'LOW',       -- LOW, MEDIUM, HIGH, CRITICAL
    extracted_entities JSONB NOT NULL DEFAULT '{}'::jsonb, -- {emails, credentials, api_keys, ips, domains, cves, high_entropy_secrets}
    matched_rules JSONB NOT NULL DEFAULT '[]'::jsonb,  -- Eşleşen kurum/izleme kuralları
    seen_sources JSONB NOT NULL DEFAULT '[]'::jsonb,   -- Aynı sızıntının görüldüğü tüm kaynaklar (Deduplication geçmişi)
    occurrence_count INTEGER NOT NULL DEFAULT 1,       -- Kaç kez karşılaşıldı
    first_seen_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    last_seen_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Hızlı arama ve filtreleme için indeksler
CREATE INDEX IF NOT EXISTS idx_leaks_risk_score ON leaks (risk_score DESC);
CREATE INDEX IF NOT EXISTS idx_leaks_severity ON leaks (severity);
CREATE INDEX IF NOT EXISTS idx_leaks_source_type ON leaks (source_type);
CREATE INDEX IF NOT EXISTS idx_leaks_last_seen ON leaks (last_seen_at DESC);
CREATE INDEX IF NOT EXISTS idx_leaks_entities_gin ON leaks USING GIN (extracted_entities);
CREATE INDEX IF NOT EXISTS idx_leaks_raw_content_trgm ON leaks USING GIN (raw_content gin_trgm_ops);
CREATE INDEX IF NOT EXISTS idx_leaks_title_trgm ON leaks USING GIN (title gin_trgm_ops);

-- 2. İzleme Kuralları (SOC Hedef Kurum / Domain / Anahtar Kelime Takibi)
CREATE TABLE IF NOT EXISTS watch_rules (
    id SERIAL PRIMARY KEY,
    rule_name VARCHAR(150) NOT NULL,
    keyword VARCHAR(255) UNIQUE NOT NULL,              -- Örn: .com.tr, lockbit, ransomware, CVE-2024
    category VARCHAR(50) DEFAULT 'DOMAIN',             -- DOMAIN, VIP_EMAIL, KEYWORD, BRAND
    risk_boost INTEGER DEFAULT 35,                     -- Eşleştiğinde eklenecek ekstra risk puanı
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- 3. Üretilen Alarmlar Tablosu (SOC Case Management)
CREATE TABLE IF NOT EXISTS alerts (
    id SERIAL PRIMARY KEY,
    leak_id INTEGER REFERENCES leaks(id) ON DELETE CASCADE,
    rule_name VARCHAR(150) NOT NULL,
    matched_keyword VARCHAR(255) NOT NULL,
    severity VARCHAR(20) NOT NULL,
    message TEXT NOT NULL,
    status VARCHAR(30) DEFAULT 'OPEN',                 -- OPEN, INVESTIGATING, RESOLVED, FALSE_POSITIVE
    analyst_note TEXT DEFAULT '',
    is_acknowledged BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_alerts_created_at ON alerts (created_at DESC);

-- 4. Toplayıcı (Scraper) Hedef Kaynaklar Tablosu (Dinamik yönetim için)
CREATE TABLE IF NOT EXISTS scraper_targets (
    id SERIAL PRIMARY KEY,
    name VARCHAR(150) NOT NULL,
    url TEXT UNIQUE NOT NULL,
    target_type VARCHAR(50) NOT NULL,                  -- darkweb_forum, threat_feed, paste_site
    use_tor BOOLEAN DEFAULT TRUE,
    interval_seconds INTEGER DEFAULT 120,
    is_active BOOLEAN DEFAULT TRUE,
    last_scraped_at TIMESTAMP WITH TIME ZONE,
    last_status VARCHAR(50) DEFAULT 'PENDING',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Başlangıç Gerçek CTI & Dark Web Tarama Hedefleri
INSERT INTO scraper_targets (name, url, target_type, use_tor, interval_seconds) VALUES
    ('Ransomware.live DarkWeb Victims (.onion Feed)', 'https://api.ransomware.live/recentvictims', 'darkweb_forum', FALSE, 120),
    ('Ahmia DarkWeb (.onion) Leak Search', 'http://juhanurmihxlp77nkq76byazcldy2hlmovfu2epvl5ankdibsot4csyd.onion/search/?q=database+leak+credentials', 'darkweb_forum', TRUE, 180),
    ('Ahmia DarkWeb (.onion) Ransomware Search', 'http://juhanurmihxlp77nkq76byazcldy2hlmovfu2epvl5ankdibsot4csyd.onion/search/?q=ransomware+dump+password', 'darkweb_forum', TRUE, 180),
    ('Abuse.ch URLhaus Malware & Stealer Feed', 'https://urlhaus.abuse.ch/downloads/text_recent/', 'paste_site', FALSE, 180),
    ('CISA Active Exploited CVEs (KEV)', 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json', 'threat_feed', FALSE, 300),
    ('Tor Project Official (.onion v3 Service)', 'http://2gzyxa5ihm7nsggfxnu52rck2vv4rvmdlkiu3zzui5du4xyclen53wid.onion/', 'darkweb_forum', TRUE, 300)
ON CONFLICT (url) DO NOTHING;

-- Başlangıç Gerçek SOC İzleme Kuralları (Watch Rules)
INSERT INTO watch_rules (rule_name, keyword, category, risk_boost) VALUES
    ('Dark Web (.onion) Sızıntı Bağlantısı', '.onion', 'DOMAIN', 35),
    ('Türkiye Uzantılı Kurumsal Hedefler', '.tr', 'DOMAIN', 45),
    ('Aktif Fidye Yazılımı (Ransomware)', 'ransomware', 'KEYWORD', 40),
    ('Kritik Veri Sızıntısı / Dump', 'credentials', 'KEYWORD', 35),
    ('Üretim / Admin Erişim İfşası', 'admin', 'KEYWORD', 30)
ON CONFLICT (keyword) DO NOTHING;
