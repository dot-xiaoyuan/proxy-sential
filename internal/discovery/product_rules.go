package discovery

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
)

type productRule struct {
	pattern            *regexp.Regexp
	kind, manufacturer string
}

type productRuleSpec struct {
	Pattern      string `json:"pattern"`
	ProductKind  string `json:"product_kind"`
	Manufacturer string `json:"manufacturer"`
}

// productRuleTable carries the rules plus the same provenance the other
// signature tables declare: a data file without a version and a source cannot
// be audited or refreshed deliberately.
type productRuleTable struct {
	Version   string            `json:"version"`
	Source    string            `json:"source"`
	SourceURL string            `json:"source_url"`
	License   string            `json:"license"`
	Entries   []productRuleSpec `json:"entries"`
}

//go:embed data/product-rules.json
var embeddedProductRules []byte

// campusProductRules is loaded from data/product-rules.json so that adding a
// consumer product family is a data change, not a release.
var campusProductRules = mustLoadProductRules(embeddedProductRules)

func mustLoadProductRules(data []byte) []productRule {
	rules, err := parseProductRules(data)
	if err != nil {
		panic(err)
	}
	return rules
}

func parseProductRules(data []byte) ([]productRule, error) {
	var table productRuleTable
	if err := json.Unmarshal(data, &table); err != nil {
		return nil, fmt.Errorf("decode product rules: %w", err)
	}
	if strings.TrimSpace(table.Version) == "" || strings.TrimSpace(table.Source) == "" {
		return nil, fmt.Errorf("product rules require a version and source")
	}
	rules := make([]productRule, 0, len(table.Entries))
	for index, spec := range table.Entries {
		if strings.TrimSpace(spec.Pattern) == "" || strings.TrimSpace(spec.ProductKind) == "" {
			return nil, fmt.Errorf("product rule %d is incomplete", index)
		}
		compiled, err := regexp.Compile(spec.Pattern)
		if err != nil {
			return nil, fmt.Errorf("compile product rule %d: %w", index, err)
		}
		rules = append(rules, productRule{pattern: compiled, kind: spec.ProductKind, manufacturer: spec.Manufacturer})
	}
	if len(rules) == 0 {
		return nil, fmt.Errorf("product rules contain no entries")
	}
	return rules, nil
}

// DNSSDModelFromTXT returns the first product/model value advertised in a
// DNS-SD TXT record. Entries are key=value pairs separated by ';' or newlines;
// only keys that name a product or model are accepted so a firmware or
// capability announcement cannot become a model.
func DNSSDModelFromTXT(text string) string {
	for _, entry := range strings.FieldsFunc(text, func(r rune) bool { return r == ';' || r == '\n' }) {
		key, value, ok := strings.Cut(entry, "=")
		if !ok {
			continue
		}
		switch strings.ToLower(strings.TrimSpace(key)) {
		case "model", "md", "product", "ty", "usb_mdl":
			model := cleanDescriptionText(strings.TrimSpace(strings.Trim(strings.TrimSpace(value), "()")))
			if model != "" {
				return model
			}
		}
	}
	return ""
}

// Only product-bearing protocol fields reach these rules. A friendly hostname,
// certificate issuer or MAC OUI cannot feed a product match.
func applyProductRules(o *Observation) {
	p := o.Evidence.Payload
	if p == nil {
		return
	}
	fields := []string{o.ModelName, str(p, "product_model"), str(p, "printer_make_and_model")}
	if o.Origin == "snmp" {
		fields = append(fields, str(p, "system_description"))
	}
	if o.Origin == "dns_sd" {
		txt := protocolText(p["txt"])
		for _, entry := range strings.FieldsFunc(txt, func(r rune) bool { return r == ';' || r == '\n' }) {
			key, value, ok := strings.Cut(entry, "=")
			if !ok {
				continue
			}
			switch strings.ToLower(strings.TrimSpace(key)) {
			case "model", "md", "product", "ty", "usb_mdl":
				fields = append(fields, value)
			}
		}
		if o.ModelName == "" {
			o.ModelName = DNSSDModelFromTXT(txt)
		}
	}
	for _, value := range fields {
		for _, rule := range campusProductRules {
			if model := rule.pattern.FindString(value); model != "" {
				// Inferred attributes belong to the observation. Never mutate the
				// input shared with archival, retries and the durable receipt hash.
				derived := make(map[string]any, len(p)+3)
				for key, value := range p {
					derived[key] = value
				}
				p = derived
				o.Evidence.Payload = derived
				p["product_verified"] = true
				p["product_type"] = rule.kind
				p["product_model"] = model
				o.ModelName = model
				if o.Manufacturer == "" {
					o.Manufacturer = rule.manufacturer
				}
				return
			}
		}
	}
}
