package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	_ "github.com/lib/pq"
	amqp "github.com/rabbitmq/amqp091-go"
	"golang.org/x/net/proxy"
)

// RawLeakEvent RabbitMQ kuyruğuna gönderilecek ham sızıntı mesajı
type RawLeakEvent struct {
	Title       string `json:"title"`
	SourceType  string `json:"source_type"`
	SourceName  string `json:"source_name"`
	SourceURL   string `json:"source_url"`
	RawContent  string `json:"raw_content"`
	CollectedAt string `json:"collected_at"`
}

// ScraperTarget veritabanından okunan dinamik tarama hedefi
type ScraperTarget struct {
	ID              int
	Name            string
	URL             string
	TargetType      string
	UseTor          bool
	IntervalSeconds int
}

type CollectorService struct {
	db          *sql.DB
	amqpConn    *amqp.Connection
	amqpChan    *amqp.Channel
	publishMu   sync.Mutex
	queueName   string
	torProxy    string
	torClient   *http.Client
	clearClient *http.Client
}

var (
	reScriptStyle = regexp.MustCompile(`(?is)<(script|style|noscript)[^>]*>.*?</(script|style|noscript)>`)
	reHTMLTags    = regexp.MustCompile(`(?s)<[^>]+>`)
	reOnionURL    = regexp.MustCompile(`http[s]?://[a-z2-7]{16,56}\.onion[^\s"'<>]*`)
	reMultiSpace  = regexp.MustCompile(`[ \t]+`)
	reMultiNewline = regexp.MustCompile(`\n{3,}`)
)

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func newTorHTTPClient(socksAddr string) (*http.Client, error) {
	dialer, err := proxy.SOCKS5("tcp", socksAddr, nil, proxy.Direct)
	if err != nil {
		return nil, err
	}
	dialContext := func(ctx context.Context, network, addr string) (net.Conn, error) {
		return dialer.Dial(network, addr)
	}
	transport := &http.Transport{
		DialContext:           dialContext,
		MaxIdleConns:          20,
		IdleConnTimeout:       30 * time.Second,
		TLSHandshakeTimeout:   20 * time.Second,
		ResponseHeaderTimeout: 30 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}
	return &http.Client{
		Transport: transport,
		Timeout:   45 * time.Second,
	}, nil
}

func connectRabbitMQ() (*amqp.Connection, *amqp.Channel, string) {
	user := getEnv("RABBITMQ_DEFAULT_USER", "cti_broker")
	pass := getEnv("RABBITMQ_DEFAULT_PASS", "cti_broker_pass")
	host := getEnv("RABBITMQ_HOST", "rabbitmq")
	port := getEnv("RABBITMQ_PORT", "5672")
	queueName := getEnv("RABBITMQ_QUEUE", "raw_leaks_queue")
	dlqName := getEnv("RABBITMQ_DLQ", "raw_leaks_dlq")

	amqpURL := fmt.Sprintf("amqp://%s:%s@%s:%s/", user, pass, host, port)

	var conn *amqp.Connection
	var err error
	for i := 1; i <= 20; i++ {
		conn, err = amqp.Dial(amqpURL)
		if err == nil {
			break
		}
		log.Printf("[RabbitMQ] Bağlantı bekleniyor (%d/20): %v", i, err)
		time.Sleep(3 * time.Second)
	}
	if err != nil {
		log.Fatalf("[RabbitMQ] Bağlantı kurulamadı: %v", err)
	}

	ch, err := conn.Channel()
	if err != nil {
		log.Fatalf("[RabbitMQ] Kanal açılamadı: %v", err)
	}

	_, err = ch.QueueDeclare(dlqName, true, false, false, false, nil)
	if err != nil {
		log.Fatalf("[RabbitMQ] DLQ oluşturulamadı: %v", err)
	}

	args := amqp.Table{
		"x-dead-letter-exchange":    "",
		"x-dead-letter-routing-key": dlqName,
	}
	_, err = ch.QueueDeclare(queueName, true, false, false, false, args)
	if err != nil {
		log.Fatalf("[RabbitMQ] Ana kuyruk oluşturulamadı: %v", err)
	}

	log.Printf("[RabbitMQ] Bağlantı başarılı. Kuyruk: %s (DLQ: %s)", queueName, dlqName)
	return conn, ch, queueName
}

func connectPostgres() *sql.DB {
	user := getEnv("POSTGRES_USER", "cti_admin")
	pass := getEnv("POSTGRES_PASSWORD", "cti_secret_pass")
	host := getEnv("POSTGRES_HOST", "postgres")
	port := getEnv("POSTGRES_PORT", "5432")
	dbName := getEnv("POSTGRES_DB", "cti_radar")

	dsn := fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=disable",
		host, port, user, pass, dbName)

	var db *sql.DB
	var err error
	for i := 1; i <= 20; i++ {
		db, err = sql.Open("postgres", dsn)
		if err == nil {
			err = db.Ping()
			if err == nil {
				break
			}
		}
		log.Printf("[PostgreSQL] Bağlantı bekleniyor (%d/20): %v", i, err)
		time.Sleep(3 * time.Second)
	}
	if err != nil {
		log.Fatalf("[PostgreSQL] Bağlantı kurulamadı: %v", err)
	}
	log.Println("[PostgreSQL] Bağlantı başarılı.")
	return db
}

func (s *CollectorService) publishEvent(event RawLeakEvent) error {
	s.publishMu.Lock()
	defer s.publishMu.Unlock()

	body, err := json.Marshal(event)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	return s.amqpChan.PublishWithContext(
		ctx,
		"",
		s.queueName,
		false,
		false,
		amqp.Publishing{
			DeliveryMode: amqp.Persistent,
			ContentType:  "application/json",
			Body:         body,
			Timestamp:    time.Now(),
		},
	)
}

func (s *CollectorService) fetchWithRetry(target ScraperTarget) (string, error) {
	client := s.clearClient
	if target.UseTor || strings.Contains(strings.ToLower(target.URL), ".onion") {
		client = s.torClient
	}

	var lastErr error
	for attempt := 1; attempt <= 3; attempt++ {
		req, err := http.NewRequest("GET", target.URL, nil)
		if err != nil {
			return "", err
		}
		req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; rv:109.0) Gecko/20100101 Firefox/115.0")
		req.Header.Set("Accept", "text/html,application/xhtml+xml,application/json;q=0.9,*/*;q=0.8")

		resp, err := client.Do(req)
		if err == nil && resp.StatusCode >= 200 && resp.StatusCode < 300 {
			limitedReader := io.LimitReader(resp.Body, 1024*1024) // Maksimum 1MB oku
			bytes, readErr := io.ReadAll(limitedReader)
			resp.Body.Close()
			if readErr == nil {
				return string(bytes), nil
			}
			lastErr = readErr
		} else if err != nil {
			lastErr = err
		} else {
			lastErr = fmt.Errorf("HTTP %d", resp.StatusCode)
			resp.Body.Close()
		}

		log.Printf("[Scraper] %s (Deneme %d/3) başarısız: %v", target.Name, attempt, lastErr)
		time.Sleep(time.Duration(attempt*3) * time.Second)
	}
	return "", lastErr
}

// cleanHTMLToText HTML içerikten script/style etiketlerini siler ve bulunan .onion linklerini koruyarak düz metne çevirir
func cleanHTMLToText(rawHTML string) string {
	onionLinks := reOnionURL.FindAllString(rawHTML, 30)
	cleaned := reScriptStyle.ReplaceAllString(rawHTML, "\n")
	cleaned = reHTMLTags.ReplaceAllString(cleaned, " ")
	cleaned = html.UnescapeString(cleaned)
	cleaned = reMultiSpace.ReplaceAllString(cleaned, " ")

	var lines []string
	for _, line := range strings.Split(cleaned, "\n") {
		trimmed := strings.TrimSpace(line)
		if len(trimmed) > 2 {
			lines = append(lines, trimmed)
		}
	}
	result := strings.Join(lines, "\n")
	result = reMultiNewline.ReplaceAllString(result, "\n\n")

	if len(result) > 4000 {
		result = result[:4000]
	}

	if len(onionLinks) > 0 {
		seen := make(map[string]bool)
		var uniqueOnions []string
		for _, link := range onionLinks {
			if !seen[link] {
				seen[link] = true
				uniqueOnions = append(uniqueOnions, link)
			}
		}
		result += "\n\n--- Tespit Edilen Dark Web (.onion) Bağlantıları ---\n" + strings.Join(uniqueOnions, "\n")
	}
	return strings.TrimSpace(result)
}

// parseAndPublishTarget çekilen gerçek veriyi kaynağın türüne göre anlamlı sızıntı olaylarına (events) dönüştürür
func (s *CollectorService) parseAndPublishTarget(target ScraperTarget, content string) int {
	nowStr := time.Now().UTC().Format(time.RFC3339)
	publishedCount := 0

	// 1. Ransomware.live Gerçek Dark Web Fidye Yazılımı Kurbanları JSON Akışı
	if strings.Contains(target.URL, "ransomware.live/recentvictims") {
		var victims []map[string]interface{}
		if err := json.Unmarshal([]byte(content), &victims); err == nil {
			limit := 15
			if len(victims) < limit {
				limit = len(victims)
			}
			for i := 0; i < limit; i++ {
				v := victims[i]
				groupName := fmt.Sprintf("%v", v["group_name"])
				victimTitle := fmt.Sprintf("%v", v["post_title"])
				country := fmt.Sprintf("%v", v["country"])
				website := fmt.Sprintf("%v", v["website"])
				desc := fmt.Sprintf("%v", v["description"])
				postURL := fmt.Sprintf("%v", v["post_url"])
				discovered := fmt.Sprintf("%v", v["discovered"])

				if postURL == "" || postURL == "<nil>" {
					postURL = target.URL
				}

				rawText := fmt.Sprintf(
					"Dark Web Ransomware Leak Alert (ransomware)\nGroup: %s\nVictim Organization: %s\nCountry: %s\nTarget Domain / Website: %s\nDiscovered At: %s\nDark Web (.onion) Leak URL: %s\nDescription: %s",
					strings.ToUpper(groupName), victimTitle, country, website, discovered, postURL, desc,
				)

				evt := RawLeakEvent{
					Title:       fmt.Sprintf("[RANSOMWARE: %s] %s (%s)", strings.ToUpper(groupName), victimTitle, country),
					SourceType:  "darkweb_forum",
					SourceName:  fmt.Sprintf("Onion Ransomware Group: %s", strings.ToUpper(groupName)),
					SourceURL:   postURL,
					RawContent:  rawText,
					CollectedAt: nowStr,
				}
				if s.publishEvent(evt) == nil {
					publishedCount++
				}
			}
			return publishedCount
		}
	}

	// 2. CISA Known Exploited Vulnerabilities (KEV) Aktif Sömürülen Gerçek CVE Akışı
	if strings.Contains(target.URL, "known_exploited_vulnerabilities.json") {
		var kevData struct {
			Vulnerabilities []struct {
				CveID                      string `json:"cveID"`
				VendorProject              string `json:"vendorProject"`
				Product                    string `json:"product"`
				VulnerabilityName          string `json:"vulnerabilityName"`
				DateAdded                  string `json:"dateAdded"`
				ShortDescription           string `json:"shortDescription"`
				KnownRansomwareCampaignUse string `json:"knownRansomwareCampaignUse"`
			} `json:"vulnerabilities"`
		}
		if err := json.Unmarshal([]byte(content), &kevData); err == nil && len(kevData.Vulnerabilities) > 0 {
			total := len(kevData.Vulnerabilities)
			start := total - 8
			if start < 0 {
				start = 0
			}
			for i := total - 1; i >= start; i-- {
				v := kevData.Vulnerabilities[i]
				rawText := fmt.Sprintf(
					"CISA Active Exploitation Advisory\nCVE ID: %s\nVendor / Product: %s - %s\nVulnerability: %s\nDate Added: %s\nRansomware Campaign Use: %s\nDetails: %s",
					v.CveID, v.VendorProject, v.Product, v.VulnerabilityName, v.DateAdded, v.KnownRansomwareCampaignUse, v.ShortDescription,
				)
				evt := RawLeakEvent{
					Title:       fmt.Sprintf("[ACTIVE EXPLOIT] %s - %s %s", v.CveID, v.VendorProject, v.Product),
					SourceType:  "paste_site",
					SourceName:  "CISA KEV Threat Feed",
					SourceURL:   fmt.Sprintf("https://nvd.nist.gov/vuln/detail/%s", v.CveID),
					RawContent:  rawText,
					CollectedAt: nowStr,
				}
				if s.publishEvent(evt) == nil {
					publishedCount++
				}
			}
			return publishedCount
		}
	}

	// 3. Abuse.ch URLhaus Aktif Zararlı Yazılım / Stealer Dağıtım URL Akışı
	if strings.Contains(target.URL, "urlhaus.abuse.ch") {
		var activeURLs []string
		for _, line := range strings.Split(content, "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			activeURLs = append(activeURLs, line)
			if len(activeURLs) >= 25 {
				break
			}
		}
		if len(activeURLs) > 0 {
			evt := RawLeakEvent{
				Title:       fmt.Sprintf("[MALWARE/STEALER C2] Abuse.ch URLhaus Son Tespit Edilen %d Zararlı Sunucu", len(activeURLs)),
				SourceType:  "paste_site",
				SourceName:  "Abuse.ch URLhaus Feed",
				SourceURL:   target.URL,
				RawContent:  "Aktif Stealer ve Zararlı Yazılım Dağıtım URL/IP Listesi (credentials / malware):\n" + strings.Join(activeURLs, "\n"),
				CollectedAt: nowStr,
			}
			if s.publishEvent(evt) == nil {
				publishedCount++
			}
			return publishedCount
		}
	}

	// 4. Genel .onion Servisi (Ahmia .onion Search, Forumlar, Tor Siteleri) veya Web/Paste Sayfası
	cleanedText := cleanHTMLToText(content)
	if cleanedText != "" {
		evt := RawLeakEvent{
			Title:       fmt.Sprintf("[LIVE SCRAPE] %s", target.Name),
			SourceType:  target.TargetType,
			SourceName:  target.Name,
			SourceURL:   target.URL,
			RawContent:  cleanedText,
			CollectedAt: nowStr,
		}
		if s.publishEvent(evt) == nil {
			publishedCount++
		}
	}
	return publishedCount
}

func (s *CollectorService) pollOnce(jobs chan<- ScraperTarget) {
	rows, err := s.db.Query(`
		SELECT id, name, url, target_type, use_tor, interval_seconds
		FROM scraper_targets
		WHERE is_active = TRUE
		  AND (last_scraped_at IS NULL OR EXTRACT(EPOCH FROM (NOW() - last_scraped_at)) >= interval_seconds)
	`)
	if err != nil {
		log.Printf("[TargetPoller] DB sorgu hatası: %v", err)
		return
	}
	defer rows.Close()

	for rows.Next() {
		var t ScraperTarget
		if err := rows.Scan(&t.ID, &t.Name, &t.URL, &t.TargetType, &t.UseTor, &t.IntervalSeconds); err == nil {
			// Aynı hedefin tekrar kuyruğa alınmaması için last_scraped_at değerini hemen güncelle
			_, _ = s.db.Exec(`UPDATE scraper_targets SET last_scraped_at = NOW(), last_status = 'SCRAPING...' WHERE id = $1`, t.ID)
			jobs <- t
		}
	}
}

func (s *CollectorService) startTargetPoller(workerCount int) {
	jobs := make(chan ScraperTarget, 30)

	for w := 1; w <= workerCount; w++ {
		go func(workerID int) {
			for target := range jobs {
				log.Printf("[Worker-%d] Gerçek kaynak taranıyor: %s (%s) [Tor=%v]", workerID, target.Name, target.URL, target.UseTor)
				content, err := s.fetchWithRetry(target)
				status := "SUCCESS"
				if err != nil {
					status = fmt.Sprintf("ERR: %v", err)
					if len(status) > 48 {
						status = status[:48]
					}
					log.Printf("[Worker-%d] Hata (%s): %v", workerID, target.Name, err)
				} else if strings.TrimSpace(content) != "" {
					count := s.parseAndPublishTarget(target, content)
					status = fmt.Sprintf("OK (%d olay)", count)
					log.Printf("[Worker-%d] %s kaynağından %d gerçek CTI olayı kuyruğa iletildi.", workerID, target.Name, count)
				}

				_, _ = s.db.Exec(`UPDATE scraper_targets SET last_scraped_at = NOW(), last_status = $1 WHERE id = $2`, status, target.ID)
			}
		}(w)
	}

	// İlk açılışta Tor düğümlerinin hazır olması için 5 sn bekle ve hemen ilk taramayı başlat
	time.Sleep(5 * time.Second)
	s.pollOnce(jobs)

	ticker := time.NewTicker(8 * time.Second)
	for range ticker.C {
		s.pollOnce(jobs)
	}
}

func main() {
	log.Println("=== Dağıtık CTI & Veri Sızıntısı Toplayıcı (Gerçek Kaynak Modu) Başlatılıyor ===")

	torProxy := getEnv("TOR_PROXY_ADDR", "haproxy-tor:9050")
	torClient, err := newTorHTTPClient(torProxy)
	if err != nil {
		log.Fatalf("[TorClient] SOCKS5 istemcisi oluşturulamadı: %v", err)
	}

	db := connectPostgres()
	defer db.Close()

	amqpConn, amqpChan, queueName := connectRabbitMQ()
	defer amqpConn.Close()
	defer amqpChan.Close()

	service := &CollectorService{
		db:        db,
		amqpConn:  amqpConn,
		amqpChan:  amqpChan,
		queueName: queueName,
		torProxy:  torProxy,
		torClient: torClient,
		clearClient: &http.Client{
			Timeout: 25 * time.Second,
		},
	}

	workerCount, _ := strconv.Atoi(getEnv("WORKER_COUNT", "5"))
	go service.startTargetPoller(workerCount)

	select {}
}
