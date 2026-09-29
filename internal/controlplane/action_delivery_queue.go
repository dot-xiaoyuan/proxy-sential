package controlplane

import "sync"

// The durable source of truth remains enforcement_actions. This queue only
// wakes two workers; a full queue leaves the intent pending for the scheduler.
type actionDeliveryQueue struct {
	once    sync.Once
	mu      sync.Mutex
	active  map[string]bool
	queue   chan actionDeliveryIntent
	deliver func(string, bool)
}

type actionDeliveryIntent struct {
	id     string
	revoke bool
}

func newActionDeliveryQueue(deliver func(string, bool)) *actionDeliveryQueue {
	return &actionDeliveryQueue{active: make(map[string]bool), queue: make(chan actionDeliveryIntent, 128), deliver: deliver}
}

func (q *actionDeliveryQueue) submit(id string, revoke bool) bool {
	q.once.Do(func() {
		for i := 0; i < 2; i++ {
			go func() {
				for intent := range q.queue {
					q.deliver(intent.id, intent.revoke)
					q.mu.Lock()
					delete(q.active, intent.id)
					q.mu.Unlock()
				}
			}()
		}
	})
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.active[id] {
		return true
	}
	q.active[id] = true
	select {
	case q.queue <- actionDeliveryIntent{id, revoke}:
		return true
	default:
		delete(q.active, id)
		return false
	}
}

func (s *Server) enqueueActionDelivery(id string, revoke bool) {
	if s.actionDeliveries != nil {
		s.actionDeliveries.submit(id, revoke)
	}
}
