package main

import (
	"strings"
	"testing"
)

func TestCleanHTMLToTextAndOnionExtraction(t *testing.T) {
	sampleHTML := `
		<html>
			<head><script>alert("xss")</script><style>body{color:red}</style></head>
			<body>
				<h1>Dark Web Leak Directory</h1>
				<p>Forum mirror: http://juhanurmihxlp77nkq76byazcldy2hlmovfu2epvl5ankdibsot4csyd.onion/search</p>
			</body>
		</html>
	`
	cleaned := cleanHTMLToText(sampleHTML)

	if strings.Contains(cleaned, "alert(") {
		t.Fatalf("Script içeriği temizlenemedi: %s", cleaned)
	}
	if !strings.Contains(cleaned, "Dark Web Leak Directory") {
		t.Fatalf("Başlık metni korunamadı: %s", cleaned)
	}
	if !strings.Contains(cleaned, "juhanurmihxlp77nkq76byazcldy2hlmovfu2epvl5ankdibsot4csyd.onion") {
		t.Fatalf(".onion bağlantısı çıkarılamadı: %s", cleaned)
	}
}
