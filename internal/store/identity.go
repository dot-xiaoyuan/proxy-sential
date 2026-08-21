package store

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
	"strconv"
	"strings"

	"proxy-sentinel/internal/normalized"
)

type IdentityState struct {
	Endpoints      []EndpointEntity
	Infrastructure []InfrastructureEntity
	Sessions       []AccountSession
	IPMACHistory   []IdentityIPMACHistory
	AccessHistory  []IdentityAccessHistory
}

type EndpointEntity struct {
	EndpointID             string         `json:"endpoint_id"`
	PrimaryMAC             string         `json:"primary_mac,omitempty"`
	EntityRole             string         `json:"entity_role"`
	FirstSeen              string         `json:"first_seen,omitempty"`
	LastSeen               string         `json:"last_seen,omitempty"`
	IdentityConfidence     float64        `json:"identity_confidence"`
	Attributes             map[string]any `json:"attributes"`
	RegistrationStatus     string         `json:"registration_status"`
	OwnerAccount           string         `json:"owner_account,omitempty"`
	OwnerName              string         `json:"owner_name,omitempty"`
	OwnerDepartment        string         `json:"owner_department,omitempty"`
	AssetTag               string         `json:"asset_tag,omitempty"`
	RegisteredBy           string         `json:"registered_by,omitempty"`
	RegisteredAt           string         `json:"registered_at,omitempty"`
	RegistrationNote       string         `json:"registration_note,omitempty"`
	MergeStatus            string         `json:"merge_status"`
	MergedIntoEndpointID   string         `json:"merged_into_endpoint_id,omitempty"`
	SplitFromEndpointID    string         `json:"split_from_endpoint_id,omitempty"`
	RegistrationUpdatedAt  string         `json:"registration_updated_at,omitempty"`
	RegistrationUpdateByID string         `json:"registration_update_by_id,omitempty"`
}

type InfrastructureEntity struct {
	EntityID   string         `json:"entity_id"`
	IP         string         `json:"ip,omitempty"`
	MAC        string         `json:"mac,omitempty"`
	EntityRole string         `json:"entity_role"`
	Name       string         `json:"name,omitempty"`
	Source     string         `json:"source"`
	FirstSeen  string         `json:"first_seen,omitempty"`
	LastSeen   string         `json:"last_seen,omitempty"`
	Attributes map[string]any `json:"attributes"`
}

type AccountSession struct {
	SessionID          string         `json:"session_id"`
	AccountID          string         `json:"account_id"`
	EndpointID         string         `json:"endpoint_id,omitempty"`
	IP                 string         `json:"ip,omitempty"`
	MAC                string         `json:"mac,omitempty"`
	AccessID           string         `json:"access_id,omitempty"`
	Source             string         `json:"source"`
	StartedAt          string         `json:"started_at"`
	EndedAt            string         `json:"ended_at,omitempty"`
	IdentityConfidence float64        `json:"identity_confidence"`
	RawRef             map[string]any `json:"raw_ref,omitempty"`
}

type IdentityIPMACHistory struct {
	EventID            string   `json:"event_id"`
	EndpointID         string   `json:"endpoint_id,omitempty"`
	AccountID          string   `json:"account_id,omitempty"`
	EntityRole         string   `json:"entity_role"`
	IP                 string   `json:"ip,omitempty"`
	MAC                string   `json:"mac,omitempty"`
	Source             string   `json:"source"`
	FirstSeen          string   `json:"first_seen"`
	LastSeen           string   `json:"last_seen"`
	IdentityConfidence float64  `json:"identity_confidence"`
	EventIDsSample     []string `json:"event_ids_sample"`
}

type IdentityAccessHistory struct {
	EventID            string   `json:"event_id"`
	EndpointID         string   `json:"endpoint_id,omitempty"`
	AccountID          string   `json:"account_id,omitempty"`
	EntityRole         string   `json:"entity_role"`
	AccessID           string   `json:"access_id"`
	AccessType         string   `json:"access_type,omitempty"`
	AP                 string   `json:"ap,omitempty"`
	SwitchID           string   `json:"switch_id,omitempty"`
	SwitchPort         string   `json:"switch_port,omitempty"`
	VLAN               string   `json:"vlan,omitempty"`
	Source             string   `json:"source"`
	FirstSeen          string   `json:"first_seen"`
	LastSeen           string   `json:"last_seen"`
	IdentityConfidence float64  `json:"identity_confidence"`
	EventIDsSample     []string `json:"event_ids_sample"`
}

type AccountIdentityProfile struct {
	AccountID     string                  `json:"account_id"`
	Summary       string                  `json:"summary"`
	Endpoints     []EndpointEntity        `json:"endpoints"`
	Sessions      []AccountSession        `json:"sessions"`
	IPHistory     []IdentityIPMACHistory  `json:"ip_history"`
	AccessHistory []IdentityAccessHistory `json:"access_history"`
	FirstSeen     string                  `json:"first_seen,omitempty"`
	LastSeen      string                  `json:"last_seen,omitempty"`
}

type EndpointIdentityProfile struct {
	EndpointID    string                  `json:"endpoint_id"`
	Summary       string                  `json:"summary"`
	Endpoint      EndpointEntity          `json:"endpoint"`
	Accounts      []string                `json:"accounts"`
	Sessions      []AccountSession        `json:"sessions"`
	IPHistory     []IdentityIPMACHistory  `json:"ip_history"`
	AccessHistory []IdentityAccessHistory `json:"access_history"`
	FirstSeen     string                  `json:"first_seen,omitempty"`
	LastSeen      string                  `json:"last_seen,omitempty"`
}

func BuildIdentityState(events []normalized.Event) IdentityState {
	state := IdentityState{
		Endpoints:      []EndpointEntity{},
		Infrastructure: []InfrastructureEntity{},
		Sessions:       []AccountSession{},
		IPMACHistory:   []IdentityIPMACHistory{},
		AccessHistory:  []IdentityAccessHistory{},
	}
	endpoints := map[string]EndpointEntity{}
	infrastructure := map[string]InfrastructureEntity{}
	sessions := map[string]AccountSession{}
	for _, event := range events {
		if event.Type != "identity" && event.Type != "device" {
			continue
		}
		fact := identityFactFromEvent(event)
		if event.Type == "device" {
			fact = identityFactFromDeviceEvent(event)
		}
		if fact.EventID == "" {
			continue
		}
		if isInfrastructureEntityRole(fact.EntityRole) {
			entity := infrastructure[fact.InfrastructureID()]
			entity = mergeInfrastructureEntity(entity, fact)
			infrastructure[entity.EntityID] = entity
			continue
		}
		if fact.EndpointID != "" && fact.EntityRole == "endpoint" {
			entity := endpoints[fact.EndpointID]
			entity = mergeEndpointEntity(entity, fact)
			endpoints[entity.EndpointID] = entity
		}
		if fact.AccountID != "" && fact.EntityRole == "endpoint" {
			session := sessions[fact.SessionID()]
			session = accountSessionFromFact(fact)
			sessions[session.SessionID] = session
		}
		if fact.IP != "" || fact.MAC != "" {
			state.IPMACHistory = append(state.IPMACHistory, IdentityIPMACHistory{
				EventID:            fact.EventID,
				EndpointID:         fact.EndpointID,
				AccountID:          fact.AccountID,
				EntityRole:         fact.EntityRole,
				IP:                 fact.IP,
				MAC:                fact.MAC,
				Source:             fact.Source,
				FirstSeen:          fact.Timestamp,
				LastSeen:           fact.Timestamp,
				IdentityConfidence: fact.Confidence,
				EventIDsSample:     []string{fact.EventID},
			})
		}
		if fact.AccessID != "" {
			state.AccessHistory = append(state.AccessHistory, IdentityAccessHistory{
				EventID:            fact.EventID,
				EndpointID:         fact.EndpointID,
				AccountID:          fact.AccountID,
				EntityRole:         fact.EntityRole,
				AccessID:           fact.AccessID,
				AccessType:         stringFromMap(fact.Payload, "access_type"),
				AP:                 firstNonEmpty(stringFromMap(fact.Payload, "ap"), fact.AccessID),
				SwitchID:           stringFromMap(fact.Payload, "switch_id"),
				SwitchPort:         stringFromMap(fact.Payload, "switch_port"),
				VLAN:               stringFromMap(fact.Payload, "vlan"),
				Source:             fact.Source,
				FirstSeen:          fact.Timestamp,
				LastSeen:           fact.Timestamp,
				IdentityConfidence: fact.Confidence,
				EventIDsSample:     []string{fact.EventID},
			})
		}
	}
	for _, endpoint := range endpoints {
		state.Endpoints = append(state.Endpoints, endpoint)
	}
	for _, entity := range infrastructure {
		state.Infrastructure = append(state.Infrastructure, entity)
	}
	for _, session := range sessions {
		state.Sessions = append(state.Sessions, session)
	}
	sort.Slice(state.Endpoints, func(i, j int) bool { return state.Endpoints[i].EndpointID < state.Endpoints[j].EndpointID })
	sort.Slice(state.Infrastructure, func(i, j int) bool { return state.Infrastructure[i].EntityID < state.Infrastructure[j].EntityID })
	sort.Slice(state.Sessions, func(i, j int) bool { return state.Sessions[i].SessionID < state.Sessions[j].SessionID })
	sort.Slice(state.IPMACHistory, func(i, j int) bool { return state.IPMACHistory[i].EventID < state.IPMACHistory[j].EventID })
	sort.Slice(state.AccessHistory, func(i, j int) bool { return state.AccessHistory[i].EventID < state.AccessHistory[j].EventID })
	return state
}

func BuildAccountIdentityProfile(state IdentityState, accountID string) (AccountIdentityProfile, bool) {
	profile := AccountIdentityProfile{
		AccountID:     accountID,
		Endpoints:     []EndpointEntity{},
		Sessions:      []AccountSession{},
		IPHistory:     []IdentityIPMACHistory{},
		AccessHistory: []IdentityAccessHistory{},
	}
	endpointIDs := map[string]struct{}{}
	for _, session := range state.Sessions {
		if session.AccountID != accountID {
			continue
		}
		profile.Sessions = append(profile.Sessions, session)
		if session.EndpointID != "" {
			endpointIDs[session.EndpointID] = struct{}{}
		}
		profile.FirstSeen = minNonEmptyTime(profile.FirstSeen, session.StartedAt)
		profile.LastSeen = maxNonEmptyTime(profile.LastSeen, firstNonEmpty(session.EndedAt, session.StartedAt))
	}
	for _, item := range state.IPMACHistory {
		if item.AccountID == accountID {
			profile.IPHistory = append(profile.IPHistory, item)
			if item.EndpointID != "" {
				endpointIDs[item.EndpointID] = struct{}{}
			}
			profile.FirstSeen = minNonEmptyTime(profile.FirstSeen, item.FirstSeen)
			profile.LastSeen = maxNonEmptyTime(profile.LastSeen, item.LastSeen)
		}
	}
	for _, item := range state.AccessHistory {
		if item.AccountID == accountID {
			profile.AccessHistory = append(profile.AccessHistory, item)
			if item.EndpointID != "" {
				endpointIDs[item.EndpointID] = struct{}{}
			}
			profile.FirstSeen = minNonEmptyTime(profile.FirstSeen, item.FirstSeen)
			profile.LastSeen = maxNonEmptyTime(profile.LastSeen, item.LastSeen)
		}
	}
	for _, endpoint := range state.Endpoints {
		if _, ok := endpointIDs[endpoint.EndpointID]; ok {
			profile.Endpoints = append(profile.Endpoints, endpoint)
		}
	}
	sort.Slice(profile.Endpoints, func(i, j int) bool { return profile.Endpoints[i].EndpointID < profile.Endpoints[j].EndpointID })
	sort.Slice(profile.Sessions, func(i, j int) bool { return profile.Sessions[i].StartedAt > profile.Sessions[j].StartedAt })
	sort.Slice(profile.IPHistory, func(i, j int) bool { return profile.IPHistory[i].LastSeen > profile.IPHistory[j].LastSeen })
	sort.Slice(profile.AccessHistory, func(i, j int) bool { return profile.AccessHistory[i].LastSeen > profile.AccessHistory[j].LastSeen })
	if len(profile.Endpoints) == 0 && len(profile.Sessions) == 0 && len(profile.IPHistory) == 0 && len(profile.AccessHistory) == 0 {
		return profile, false
	}
	profile.Summary = identitySummary("账号", accountID, len(profile.Endpoints), uniqueIdentityValues(profile.IPHistory, func(item IdentityIPMACHistory) string { return item.IP }), uniqueAccessIDs(profile.AccessHistory))
	return profile, true
}

func BuildEndpointIdentityProfile(state IdentityState, endpointID string) (EndpointIdentityProfile, bool) {
	profile := EndpointIdentityProfile{
		EndpointID:    endpointID,
		Accounts:      []string{},
		Sessions:      []AccountSession{},
		IPHistory:     []IdentityIPMACHistory{},
		AccessHistory: []IdentityAccessHistory{},
	}
	accountSet := map[string]struct{}{}
	for _, endpoint := range state.Endpoints {
		if endpoint.EndpointID == endpointID {
			profile.Endpoint = endpoint
			profile.FirstSeen = minNonEmptyTime(profile.FirstSeen, endpoint.FirstSeen)
			profile.LastSeen = maxNonEmptyTime(profile.LastSeen, endpoint.LastSeen)
			break
		}
	}
	for _, session := range state.Sessions {
		if session.EndpointID != endpointID {
			continue
		}
		profile.Sessions = append(profile.Sessions, session)
		if session.AccountID != "" {
			accountSet[session.AccountID] = struct{}{}
		}
		profile.FirstSeen = minNonEmptyTime(profile.FirstSeen, session.StartedAt)
		profile.LastSeen = maxNonEmptyTime(profile.LastSeen, firstNonEmpty(session.EndedAt, session.StartedAt))
	}
	for _, item := range state.IPMACHistory {
		if item.EndpointID == endpointID {
			profile.IPHistory = append(profile.IPHistory, item)
			if item.AccountID != "" {
				accountSet[item.AccountID] = struct{}{}
			}
			profile.FirstSeen = minNonEmptyTime(profile.FirstSeen, item.FirstSeen)
			profile.LastSeen = maxNonEmptyTime(profile.LastSeen, item.LastSeen)
		}
	}
	for _, item := range state.AccessHistory {
		if item.EndpointID == endpointID {
			profile.AccessHistory = append(profile.AccessHistory, item)
			if item.AccountID != "" {
				accountSet[item.AccountID] = struct{}{}
			}
			profile.FirstSeen = minNonEmptyTime(profile.FirstSeen, item.FirstSeen)
			profile.LastSeen = maxNonEmptyTime(profile.LastSeen, item.LastSeen)
		}
	}
	for accountID := range accountSet {
		profile.Accounts = append(profile.Accounts, accountID)
	}
	sort.Strings(profile.Accounts)
	sort.Slice(profile.Sessions, func(i, j int) bool { return profile.Sessions[i].StartedAt > profile.Sessions[j].StartedAt })
	sort.Slice(profile.IPHistory, func(i, j int) bool { return profile.IPHistory[i].LastSeen > profile.IPHistory[j].LastSeen })
	sort.Slice(profile.AccessHistory, func(i, j int) bool { return profile.AccessHistory[i].LastSeen > profile.AccessHistory[j].LastSeen })
	if profile.Endpoint.EndpointID == "" && len(profile.Sessions) == 0 && len(profile.IPHistory) == 0 && len(profile.AccessHistory) == 0 {
		return profile, false
	}
	profile.Summary = identitySummary("终端", endpointID, len(profile.Accounts), uniqueIdentityValues(profile.IPHistory, func(item IdentityIPMACHistory) string { return item.IP }), uniqueAccessIDs(profile.AccessHistory))
	return profile, true
}

func BuildEndpointDeviceInventory(profile EndpointIdentityProfile) EndpointDeviceInventory {
	endpoint := profile.Endpoint
	ensureEndpointRegistrationDefaults(&endpoint)
	ips := uniqueIdentityValues(profile.IPHistory, func(item IdentityIPMACHistory) string { return item.IP })
	accessIDs := uniqueAccessIDs(profile.AccessHistory)
	item := EndpointDeviceInventory{
		EndpointID:         profile.EndpointID,
		PrimaryMAC:         endpoint.PrimaryMAC,
		EntityRole:         endpoint.EntityRole,
		RegistrationStatus: endpoint.RegistrationStatus,
		OwnerAccount:       endpoint.OwnerAccount,
		OwnerName:          endpoint.OwnerName,
		OwnerDepartment:    endpoint.OwnerDepartment,
		AssetTag:           endpoint.AssetTag,
		MergeStatus:        endpoint.MergeStatus,
		CurrentAccount:     firstString(profile.Accounts),
		CurrentIP:          firstString(ips),
		CurrentAccessID:    firstString(accessIDs),
		Accounts:           append([]string{}, profile.Accounts...),
		IPs:                ips,
		AccessIDs:          accessIDs,
		FirstSeen:          profile.FirstSeen,
		LastSeen:           profile.LastSeen,
		IdentityConfidence: endpoint.IdentityConfidence,
	}
	if item.FirstSeen == "" {
		item.FirstSeen = endpoint.FirstSeen
	}
	if item.LastSeen == "" {
		item.LastSeen = endpoint.LastSeen
	}
	item.Summary = endpointDeviceSummary(item)
	return item
}

func BuildEndpointDeviceInventories(state IdentityState, query Query) []EndpointDeviceInventory {
	items := []EndpointDeviceInventory{}
	for _, endpoint := range state.Endpoints {
		if endpoint.EntityRole != "endpoint" {
			continue
		}
		profile, ok := BuildEndpointIdentityProfile(state, endpoint.EndpointID)
		if !ok {
			continue
		}
		item := BuildEndpointDeviceInventory(profile)
		if endpointDeviceMatchesQuery(item, query) {
			items = append(items, item)
		}
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].LastSeen != items[j].LastSeen {
			return items[i].LastSeen > items[j].LastSeen
		}
		return items[i].EndpointID < items[j].EndpointID
	})
	return items
}

func endpointDeviceMatchesQuery(item EndpointDeviceInventory, query Query) bool {
	if query.SrcIP != "" && item.CurrentIP != query.SrcIP && !stringSliceContains(item.IPs, query.SrcIP) {
		return false
	}
	q := strings.ToLower(strings.TrimSpace(query.Q))
	if q == "" {
		return true
	}
	values := []string{
		item.EndpointID,
		item.PrimaryMAC,
		item.RegistrationStatus,
		item.OwnerAccount,
		item.OwnerName,
		item.OwnerDepartment,
		item.AssetTag,
		item.CurrentAccount,
		item.CurrentIP,
		item.CurrentAccessID,
		item.Summary,
	}
	values = append(values, item.Accounts...)
	values = append(values, item.IPs...)
	values = append(values, item.AccessIDs...)
	for _, value := range values {
		if strings.Contains(strings.ToLower(value), q) {
			return true
		}
	}
	return false
}

func endpointDeviceSummary(item EndpointDeviceInventory) string {
	owner := firstNonEmpty(item.OwnerName, item.OwnerAccount, "未登记责任人")
	return "终端 " + item.EndpointID + "，登记状态 " + item.RegistrationStatus + "，责任人 " + owner + "，观察到 " + stringInt(len(item.IPs)) + " 个 IP、" + stringInt(len(item.AccessIDs)) + " 个接入位置"
}

type identityFact struct {
	EventID    string
	Timestamp  string
	Source     string
	IP         string
	MAC        string
	AccountID  string
	EndpointID string
	AccessID   string
	EntityRole string
	Confidence float64
	Payload    map[string]any
	RawRef     map[string]any
}

func identityFactFromEvent(event normalized.Event) identityFact {
	role := stringFromMap(event.Subject, "entity_role")
	if role == "" {
		role = "unknown"
	}
	source := stringFromMap(event.Payload, "origin")
	if source == "" {
		source = event.Source
	}
	conf := event.Confidence
	if value, ok := event.Subject["identity_confidence"].(float64); ok {
		conf = value
	}
	return identityFact{
		EventID:    event.EventID,
		Timestamp:  event.Timestamp,
		Source:     source,
		IP:         stringFromMap(event.Subject, "ip"),
		MAC:        normalizeSignalValue("mac", stringFromMap(event.Subject, "mac")),
		AccountID:  firstNonEmpty(stringFromMap(event.Subject, "account_id"), stringFromMap(event.Subject, "user_id")),
		EndpointID: stringFromMap(event.Subject, "endpoint_id"),
		AccessID:   stringFromMap(event.Subject, "access_id"),
		EntityRole: role,
		Confidence: conf,
		Payload:    event.Payload,
		RawRef:     event.RawRef,
	}
}

func identityFactFromDeviceEvent(event normalized.Event) identityFact {
	mac := normalizeSignalValue("mac", firstNonEmpty(
		stringFromMap(event.Subject, "mac"),
		stringFromMap(event.Payload, "mac"),
		stringFromMap(event.Payload, "client_mac"),
		stringFromMap(event.Payload, "client_chaddr"),
	))
	if mac == "" {
		return identityFact{}
	}
	ip := firstNonEmpty(
		stringFromMap(event.Subject, "ip"),
		stringFromMap(event.Payload, "assigned_addr"),
		stringFromMap(event.Flow, "src_ip"),
	)
	source := firstNonEmpty(stringFromMap(event.Payload, "origin"), event.Source)
	return identityFact{
		EventID:    event.EventID,
		Timestamp:  event.Timestamp,
		Source:     source,
		IP:         ip,
		MAC:        mac,
		EndpointID: "mac:" + mac,
		EntityRole: "endpoint",
		Confidence: event.Confidence,
		Payload:    event.Payload,
		RawRef:     event.RawRef,
	}
}

func (f identityFact) SessionID() string {
	if sessionID := stringFromMap(f.Payload, "session_id"); sessionID != "" {
		return sessionID
	}
	return "session-" + shortHash(strings.Join([]string{f.AccountID, f.EndpointID, f.IP, f.AccessID, f.EventID}, "|"))
}

func (f identityFact) InfrastructureID() string {
	if f.EndpointID != "" {
		return f.EndpointID
	}
	if f.IP != "" {
		return "ip:" + f.IP
	}
	if f.MAC != "" {
		return "mac:" + f.MAC
	}
	return "infra-" + shortHash(f.EventID)
}

func mergeEndpointEntity(current EndpointEntity, fact identityFact) EndpointEntity {
	if current.EndpointID == "" {
		current = EndpointEntity{
			EndpointID:         fact.EndpointID,
			PrimaryMAC:         fact.MAC,
			EntityRole:         "endpoint",
			FirstSeen:          fact.Timestamp,
			LastSeen:           fact.Timestamp,
			IdentityConfidence: fact.Confidence,
			Attributes:         identityAttributes(fact),
			RegistrationStatus: "unregistered",
			MergeStatus:        "active",
		}
		return current
	}
	if current.PrimaryMAC == "" {
		current.PrimaryMAC = fact.MAC
	}
	current.FirstSeen = minNonEmptyTime(current.FirstSeen, fact.Timestamp)
	current.LastSeen = maxNonEmptyTime(current.LastSeen, fact.Timestamp)
	if fact.Confidence > current.IdentityConfidence {
		current.IdentityConfidence = fact.Confidence
	}
	ensureEndpointRegistrationDefaults(&current)
	return current
}

func ensureEndpointRegistrationDefaults(endpoint *EndpointEntity) {
	if endpoint.RegistrationStatus == "" {
		endpoint.RegistrationStatus = "unregistered"
	}
	if endpoint.MergeStatus == "" {
		endpoint.MergeStatus = "active"
	}
	if endpoint.Attributes == nil {
		endpoint.Attributes = map[string]any{}
	}
}

func mergeInfrastructureEntity(current InfrastructureEntity, fact identityFact) InfrastructureEntity {
	if current.EntityID == "" {
		return InfrastructureEntity{
			EntityID:   fact.InfrastructureID(),
			IP:         fact.IP,
			MAC:        fact.MAC,
			EntityRole: fact.EntityRole,
			Name:       firstNonEmpty(stringFromMap(fact.Payload, "name"), fact.AccessID, fact.IP),
			Source:     fact.Source,
			FirstSeen:  fact.Timestamp,
			LastSeen:   fact.Timestamp,
			Attributes: identityAttributes(fact),
		}
	}
	current.FirstSeen = minNonEmptyTime(current.FirstSeen, fact.Timestamp)
	current.LastSeen = maxNonEmptyTime(current.LastSeen, fact.Timestamp)
	return current
}

func accountSessionFromFact(fact identityFact) AccountSession {
	return AccountSession{
		SessionID:          fact.SessionID(),
		AccountID:          fact.AccountID,
		EndpointID:         fact.EndpointID,
		IP:                 fact.IP,
		MAC:                fact.MAC,
		AccessID:           fact.AccessID,
		Source:             fact.Source,
		StartedAt:          fact.Timestamp,
		IdentityConfidence: fact.Confidence,
		RawRef:             fact.RawRef,
	}
}

func identityAttributes(fact identityFact) map[string]any {
	attrs := map[string]any{}
	for _, key := range []string{"auth_method", "vlan", "ap", "switch_id", "switch_port", "nas_ip", "nas_port_id", "hostname", "client_fqdn", "vendor_class"} {
		if value := stringFromMap(fact.Payload, key); value != "" {
			attrs[key] = value
		}
	}
	return attrs
}

func minNonEmptyTime(left, right string) string {
	if left == "" {
		return right
	}
	if right == "" || left < right {
		return left
	}
	return right
}

func maxNonEmptyTime(left, right string) string {
	if left == "" || right > left {
		return right
	}
	return left
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

func identitySummary(label, id string, primaryCount int, ips []string, accessIDs []string) string {
	parts := []string{label + " " + id}
	if primaryCount > 0 {
		parts = append(parts, "关联对象数 "+stringInt(primaryCount))
	}
	if len(ips) > 0 {
		parts = append(parts, "IP "+stringInt(len(ips)))
	}
	if len(accessIDs) > 0 {
		parts = append(parts, "接入位置 "+stringInt(len(accessIDs)))
	}
	return strings.Join(parts, "，")
}

func uniqueIdentityValues[T any](items []T, pick func(T) string) []string {
	seen := map[string]struct{}{}
	for _, item := range items {
		value := pick(item)
		if value != "" {
			seen[value] = struct{}{}
		}
	}
	values := make([]string, 0, len(seen))
	for value := range seen {
		values = append(values, value)
	}
	sort.Strings(values)
	return values
}

func uniqueAccessIDs(items []IdentityAccessHistory) []string {
	return uniqueIdentityValues(items, func(item IdentityAccessHistory) string { return item.AccessID })
}

func firstString(values []string) string {
	if len(values) == 0 {
		return ""
	}
	return values[0]
}

func stringSliceContains(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func stringInt(value int) string {
	return strconv.Itoa(value)
}

func identityJSON(value any) []byte {
	data, _ := json.Marshal(value)
	return data
}

func stableIdentityID(parts ...string) string {
	sum := sha256.Sum256([]byte(strings.Join(parts, "|")))
	return hex.EncodeToString(sum[:])[:20]
}
