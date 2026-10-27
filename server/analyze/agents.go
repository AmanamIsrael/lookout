package analyze

import "strings"

// Agent is a self-declared bot or AI agent we can recognise by user agent.
type Agent struct {
	Token    string `json:"token"`    // substring in the User-Agent
	Operator string `json:"operator"` // who runs it
	Kind     string `json:"kind"`     // search | ai_crawler | ai_search | ai_assistant
	// RDNS lists the domains its IPs reverse-resolve to. Empty means the
	// operator publishes no reverse-DNS check; Web Bot Auth may still apply.
	RDNS []string `json:"-"`
}

// IsAI reports whether the agent serves an AI product.
func (a Agent) IsAI() bool { return strings.HasPrefix(a.Kind, "ai_") }

var knownAgents = []Agent{
	{Token: "Googlebot", Operator: "Google", Kind: "search", RDNS: []string{"googlebot.com", "google.com"}},
	{Token: "Google-CloudVertexBot", Operator: "Google", Kind: "ai_crawler", RDNS: []string{"google.com"}},
	{Token: "bingbot", Operator: "Microsoft", Kind: "search", RDNS: []string{"search.msn.com"}},
	{Token: "Applebot", Operator: "Apple", Kind: "search", RDNS: []string{"applebot.apple.com"}},
	{Token: "YandexBot", Operator: "Yandex", Kind: "search", RDNS: []string{"yandex.ru", "yandex.net", "yandex.com"}},
	{Token: "Baiduspider", Operator: "Baidu", Kind: "search", RDNS: []string{"baidu.com", "baidu.jp"}},
	{Token: "DuckDuckBot", Operator: "DuckDuckGo", Kind: "search"},
	{Token: "Amazonbot", Operator: "Amazon", Kind: "ai_crawler", RDNS: []string{"crawl.amazonbot.amazon"}},
	{Token: "GPTBot", Operator: "OpenAI", Kind: "ai_crawler"},
	{Token: "OAI-SearchBot", Operator: "OpenAI", Kind: "ai_search"},
	{Token: "ChatGPT-User", Operator: "OpenAI", Kind: "ai_assistant"},
	{Token: "ChatGPT Agent", Operator: "OpenAI", Kind: "ai_assistant"},
	{Token: "ClaudeBot", Operator: "Anthropic", Kind: "ai_crawler"},
	{Token: "Claude-SearchBot", Operator: "Anthropic", Kind: "ai_search"},
	{Token: "Claude-User", Operator: "Anthropic", Kind: "ai_assistant"},
	{Token: "PerplexityBot", Operator: "Perplexity", Kind: "ai_search"},
	{Token: "Perplexity-User", Operator: "Perplexity", Kind: "ai_assistant"},
	{Token: "MistralAI-User", Operator: "Mistral", Kind: "ai_assistant"},
	{Token: "DuckAssistBot", Operator: "DuckDuckGo", Kind: "ai_assistant"},
	{Token: "meta-externalagent", Operator: "Meta", Kind: "ai_crawler"},
	{Token: "Bytespider", Operator: "ByteDance", Kind: "ai_crawler"},
	{Token: "CCBot", Operator: "Common Crawl", Kind: "ai_crawler"},
	{Token: "cohere-ai", Operator: "Cohere", Kind: "ai_crawler"},
	{Token: "Diffbot", Operator: "Diffbot", Kind: "ai_crawler"},
}

// ClaimedAgent returns the known agent a User-Agent declares, if any.
func ClaimedAgent(ua string) (Agent, bool) {
	lower := strings.ToLower(ua)
	for _, a := range knownAgents {
		if strings.Contains(lower, strings.ToLower(a.Token)) {
			return a, true
		}
	}
	return Agent{}, false
}

// Tools that announce themselves in the User-Agent.
var automationTokens = []string{
	"python-requests", "python-urllib", "aiohttp", "httpx", "curl/", "wget/", "go-http-client",
	"axios/", "node-fetch", "undici", "got (", "okhttp", "java/", "apache-httpclient", "libwww-perl",
	"scrapy", "headlesschrome", "phantomjs", "puppeteer", "playwright", "selenium", "httpie",
	"postmanruntime", "insomnia", "zgrab", "masscan", "nmap", "nikto", "sqlmap", "nuclei", "gobuster",
	"ffuf", "dirbuster", "wpscan",
}

// Tools that only ever probe for vulnerabilities.
var scannerTokens = []string{"zgrab", "masscan", "nmap", "nikto", "sqlmap", "nuclei", "gobuster", "ffuf", "dirbuster", "wpscan"}

func matchToken(ua string, tokens []string) string {
	lower := strings.ToLower(ua)
	for _, t := range tokens {
		if strings.Contains(lower, t) {
			return strings.TrimRight(t, "/ (")
		}
	}
	return ""
}

// browserFamily returns chrome, firefox or safari when the User-Agent claims
// to be a mainstream browser, or "" otherwise.
func browserFamily(ua string) string {
	if !strings.HasPrefix(ua, "Mozilla/5.0") {
		return ""
	}
	lower := strings.ToLower(ua)
	for _, t := range []string{"bot", "crawl", "spider", "headless", "http"} {
		if strings.Contains(lower, t) {
			return ""
		}
	}
	switch {
	case strings.Contains(ua, "Chrome/") || strings.Contains(ua, "CriOS/") || strings.Contains(ua, "Edg/"):
		return "chrome"
	case strings.Contains(ua, "Firefox/"):
		return "firefox"
	case strings.Contains(ua, "Safari/"):
		return "safari"
	}
	return ""
}
