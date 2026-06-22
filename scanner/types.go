package scanner

type Severity string

const (
	Critical Severity = "critical"
	High     Severity = "high"
	Medium   Severity = "medium"
	Low      Severity = "low"
	Info     Severity = "info"
)

type CheckResult struct {
	CheckName   string   `json:"check_name"`
	Passed      bool     `json:"passed"`
	Severity    Severity `json:"severity"`
	Title       string   `json:"title"`
	Description string   `json:"description"`
	Evidence    string   `json:"evidence,omitempty"`
	FixHint     string   `json:"fix_hint,omitempty"`
}

type ScanResult struct {
	Domain       string        `json:"domain"`
	Score        int           `json:"score"`
	Checks       []CheckResult `json:"checks"`
	AIAnalysis   []AIVuln      `json:"ai_analysis,omitempty"`
	ScannedAt    string        `json:"scanned_at"`
}

type AIVuln struct {
	CheckName   string `json:"check_name"`
	Explanation string `json:"explanation"`
	RiskLevel   string `json:"risk_level"`
	HowToExploit string `json:"how_to_exploit"`
	HowToFix    string `json:"how_to_fix"`
	CodeSnippet string `json:"code_snippet,omitempty"`
}

func CalculateScore(checks []CheckResult) int {
	if len(checks) == 0 {
		return 100
	}
	deductions := map[Severity]int{
		Critical: 25,
		High:     15,
		Medium:   8,
		Low:      3,
		Info:     0,
	}
	score := 100
	for _, c := range checks {
		if !c.Passed {
			score -= deductions[c.Severity]
		}
	}
	if score < 0 {
		score = 0
	}
	return score
}
