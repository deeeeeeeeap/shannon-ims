package vowifihost

import "sync"

type StateHub struct {
	mu     sync.RWMutex
	nextID uint64
	subs   map[string]map[uint64]chan struct{}
}

func NewStateHub() *StateHub {
	return &StateHub{subs: make(map[string]map[uint64]chan struct{})}
}

func (h *StateHub) Subscribe(deviceID string) (<-chan struct{}, func()) {
	if h == nil {
		h = NewStateHub()
	}

	ch := make(chan struct{}, 1)

	h.mu.Lock()
	if h.subs == nil {
		h.subs = make(map[string]map[uint64]chan struct{})
	}
	h.nextID++
	subID := h.nextID
	if h.subs[deviceID] == nil {
		h.subs[deviceID] = make(map[uint64]chan struct{})
	}
	h.subs[deviceID][subID] = ch
	h.mu.Unlock()

	unsub := func() {
		h.mu.Lock()
		defer h.mu.Unlock()
		if subs, ok := h.subs[deviceID]; ok {
			delete(subs, subID)
			if len(subs) == 0 {
				delete(h.subs, deviceID)
			}
		}
	}

	return ch, unsub
}

func (h *StateHub) Broadcast(deviceID string) {
	if h == nil {
		return
	}

	h.mu.RLock()
	subs, ok := h.subs[deviceID]
	if !ok || len(subs) == 0 {
		h.mu.RUnlock()
		return
	}
	listeners := make([]chan struct{}, 0, len(subs))
	for _, ch := range subs {
		listeners = append(listeners, ch)
	}
	h.mu.RUnlock()

	for _, ch := range listeners {
		select {
		case ch <- struct{}{}:
		default:
		}
	}
}

func (h *StateHub) SubscriberCount(deviceID string) int {
	if h == nil {
		return 0
	}
	h.mu.RLock()
	defer h.mu.RUnlock()
	return len(h.subs[deviceID])
}
