package poison

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

type replayLine struct {
	RuleID        string   `json:"rule_id"`
	Name          string   `json:"name"`
	Enabled       *bool    `json:"enabled"`
	BehaviorType  string   `json:"behavior_type"`
	TargetType    string   `json:"target_type"`
	Targets       []string `json:"targets"`
	WindowSeconds int      `json:"window_seconds"`
	Threshold     int      `json:"threshold"`
	Direction     string   `json:"direction"`
	SubjectIP     string   `json:"subject_ip"`
	DstIP         string   `json:"dst_ip"`
	Proto         string   `json:"proto"`
	At            string   `json:"at"`
	Count         int      `json:"count"`
}

// loadReplay reads a fixture whose first line is the rule and whose remaining
// lines are observations, so a case is self-describing and reviewable.
func loadReplay(t *testing.T, path string) (Rule, []Observation) {
	t.Helper()
	file, err := os.Open(filepath.Join("..", "..", "examples", "replay", path))
	if err != nil {
		t.Fatalf("open fixture: %v", err)
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 64*1024), 1<<20)
	rule := Rule{}
	observations := []Observation{}
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}
		var decoded replayLine
		if err := json.Unmarshal(line, &decoded); err != nil {
			t.Fatalf("decode fixture line: %v", err)
		}
		if decoded.RuleID != "" && decoded.SubjectIP == "" {
			enabled := true
			if decoded.Enabled != nil {
				enabled = *decoded.Enabled
			}
			rule = Rule{RuleID: decoded.RuleID, Name: decoded.Name, Enabled: enabled, BehaviorType: decoded.BehaviorType, TargetType: decoded.TargetType, Targets: decoded.Targets, WindowSeconds: decoded.WindowSeconds, Threshold: decoded.Threshold, Direction: decoded.Direction}
			continue
		}
		at, err := time.Parse(time.RFC3339, decoded.At)
		if err != nil {
			t.Fatalf("decode fixture timestamp %q: %v", decoded.At, err)
		}
		observations = append(observations, Observation{SubjectIP: decoded.SubjectIP, DstIP: decoded.DstIP, Proto: decoded.Proto, Direction: decoded.Direction, At: at, Count: decoded.Count})
	}
	if rule.RuleID == "" {
		t.Fatal("fixture is missing the rule line")
	}
	return rule, observations
}

func TestReplaySensitiveRangeCase(t *testing.T) {
	rule, observations := loadReplay(t, "destination-target-sensitive.jsonl")
	if err := ValidateRule(&rule); err != nil {
		t.Fatalf("fixture rule must be valid: %v", err)
	}
	findings := Evaluate(rule, observations)
	if len(findings) != 1 {
		t.Fatalf("expected one subject to fire, got %+v", findings)
	}
	finding := findings[0]
	if finding.SubjectIP != "10.155.9.9" {
		t.Fatalf("unexpected subject: %+v", finding)
	}
	// The public destination must not contribute to the internal-target count.
	if finding.HitCount != 6 || finding.UniqueDestinations != 3 {
		t.Fatalf("public destinations must be excluded: %+v", finding)
	}
	if len(finding.MatchedTargets) != 2 {
		t.Fatalf("both sensitive targets must be reported: %+v", finding.MatchedTargets)
	}
}

func TestReplayNegativeCaseNeverFires(t *testing.T) {
	rule, observations := loadReplay(t, "destination-target-negative.jsonl")
	if err := ValidateRule(&rule); err != nil {
		t.Fatalf("fixture rule must be valid: %v", err)
	}
	if findings := Evaluate(rule, observations); len(findings) != 0 {
		t.Fatalf("negative fixture must not fire: %+v", findings)
	}
}
