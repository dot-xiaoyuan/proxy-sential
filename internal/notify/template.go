// Package notify renders notification templates and delivers them through
// configured channels. Rendering is a whitelisted placeholder substitution: no
// expression evaluation, no template engine, no caller-supplied function calls.
package notify

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// AllowedVariables is the closed vocabulary a template may reference. Adding a
// variable is a deliberate contract change: the control plane must be able to
// supply it at delivery time.
var AllowedVariables = []string{
	"account",
	"brand",
	"campus",
	"contact_number",
	"date",
	"evidence_summary",
	"ip",
	"mac",
	"model",
	"name",
	"occurred_at",
	"policy_name",
	"student_id",
	"vlan",
}

var allowedVariableSet = func() map[string]bool {
	set := make(map[string]bool, len(AllowedVariables))
	for _, name := range AllowedVariables {
		set[name] = true
	}
	return set
}()

// placeholderPattern matches {{name}} with an identifier-only body. Anything
// else (including unbalanced braces) is left untouched and never executed.
var placeholderPattern = regexp.MustCompile(`\{\{\s*([a-z_][a-z0-9_]*)\s*\}\}`)

type Template struct {
	TemplateID  string   `json:"template_id"`
	Name        string   `json:"name"`
	ChannelType string   `json:"channel_type,omitempty"`
	Subject     string   `json:"subject,omitempty"`
	Body        string   `json:"body"`
	Variables   []string `json:"variables"`
	Enabled     bool     `json:"enabled"`
	Revision    int      `json:"revision"`
}

// Placeholders returns the distinct variable names referenced by the template,
// in deterministic order, including names outside the allowed vocabulary.
func (t Template) Placeholders() []string {
	seen := map[string]bool{}
	for _, candidate := range append([]string{t.Subject}, t.Body) {
		for _, match := range placeholderPattern.FindAllStringSubmatch(candidate, -1) {
			seen[match[1]] = true
		}
	}
	names := make([]string, 0, len(seen))
	for name := range seen {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func ValidateTemplate(t *Template) error {
	if t == nil {
		return fmt.Errorf("模板不能为空")
	}
	t.TemplateID = strings.TrimSpace(t.TemplateID)
	t.Name = strings.TrimSpace(t.Name)
	t.Subject = strings.TrimSpace(t.Subject)
	t.ChannelType = strings.TrimSpace(t.ChannelType)
	if t.TemplateID == "" || t.Name == "" {
		return fmt.Errorf("模板标识与名称不能为空")
	}
	if len(t.TemplateID) > 128 || len(t.Name) > 128 {
		return fmt.Errorf("模板标识或名称过长")
	}
	if strings.TrimSpace(t.Body) == "" {
		return fmt.Errorf("模板正文不能为空")
	}
	if len(t.Body) > 8192 || len(t.Subject) > 512 {
		return fmt.Errorf("模板正文或标题超出长度限制")
	}
	for _, name := range t.Placeholders() {
		if !allowedVariableSet[name] {
			return fmt.Errorf("模板引用了不支持的变量 %q", name)
		}
	}
	if t.Revision < 1 {
		t.Revision = 1
	}
	t.Variables = t.Placeholders()
	return nil
}

// Render substitutes the supplied variables. Missing variables render as an
// empty string and are reported so the caller can record an explanation rather
// than silently sending a half-empty message.
func (t Template) Render(values map[string]string) (subject string, body string, missing []string) {
	missingSet := map[string]bool{}
	substitute := func(input string) string {
		return placeholderPattern.ReplaceAllStringFunc(input, func(match string) string {
			name := placeholderPattern.FindStringSubmatch(match)[1]
			if value, ok := values[name]; ok {
				return value
			}
			missingSet[name] = true
			return ""
		})
	}
	subject = substitute(t.Subject)
	body = substitute(t.Body)
	for name := range missingSet {
		missing = append(missing, name)
	}
	sort.Strings(missing)
	return subject, body, missing
}
