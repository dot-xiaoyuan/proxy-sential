package violation

import (
	"slices"
	"time"
)

const NoticeInterval = 48 * time.Hour

type Interval struct{ Start, End time.Time }

func ContinuousOnline(intervals []Interval, now time.Time, duration, toleratedGap time.Duration) bool {
	if len(intervals) == 0 {
		return false
	}
	copyOf := slices.Clone(intervals)
	slices.SortFunc(copyOf, func(a, b Interval) int { return a.Start.Compare(b.Start) })
	start, end := copyOf[0].Start, copyOf[0].End
	for _, item := range copyOf[1:] {
		if item.Start.Sub(end) > toleratedGap {
			start = item.Start
		}
		if item.End.After(end) {
			end = item.End
		}
	}
	return !start.After(now.Add(-duration)) && !end.Before(now.Add(-15*time.Minute))
}

func RouterEligible(role string, confirmed, ambiguous bool, accounts []string, fresh bool) bool {
	return role == "router" && confirmed && !ambiguous && fresh && len(accounts) == 1 && accounts[0] != ""
}

type Case struct {
	CaseID         string      `json:"case_id"`
	AccountID      string      `json:"account_id"`
	AssessmentID   string      `json:"assessment_id"`
	Status         string      `json:"status"`
	FirstSeen      time.Time   `json:"first_seen"`
	LastSeen       time.Time   `json:"last_seen"`
	NoticeTimes    []time.Time `json:"simulated_notice_times"`
	PriorSanctions int         `json:"prior_sanctions"`
	LastViolation  time.Time   `json:"last_violation"`
}

func (c *Case) AdvanceNotice(now time.Time, eligible bool) bool {
	if !eligible || c.Status != "open" || len(c.NoticeTimes) >= 3 {
		return false
	}
	if n := len(c.NoticeTimes); n > 0 && now.Sub(c.NoticeTimes[n-1]) < NoticeInterval {
		return false
	}
	c.NoticeTimes = append(c.NoticeTimes, now)
	return true
}

type Decision struct {
	Kind            string    `json:"kind"`
	Reason          string    `json:"reason"`
	DurationDays    int       `json:"duration_days,omitempty"`
	ExpectedRelease time.Time `json:"expected_release,omitempty"`
}

func (c Case) Decide(now time.Time, fresh, whitelisted, identityConflict bool) Decision {
	if c.Status != "open" || !fresh || whitelisted || identityConflict {
		return Decision{Kind: "阻止", Reason: "案件、证据、身份或白名单条件未满足"}
	}
	local := now.In(time.FixedZone("Asia/Shanghai", 8*3600))
	if local.Hour() < 1 || local.Hour() >= 5 {
		return Decision{Kind: "阻止", Reason: "不在 01:00–05:00 观察窗口"}
	}
	if len(c.NoticeTimes) != 3 || now.Sub(c.NoticeTimes[2]) < NoticeInterval {
		return Decision{Kind: "阻止", Reason: "三次拟提醒及宽限期未完成"}
	}
	prior := c.PriorSanctions
	if !c.LastViolation.IsZero() && now.Sub(c.LastViolation) >= 90*24*time.Hour {
		prior = 0
	}
	days := min(prior+1, 7)
	return Decision{Kind: "拟封禁", Reason: "观察模式，不会提交外部动作", DurationDays: days, ExpectedRelease: now.Add(time.Duration(days) * 24 * time.Hour)}
}
