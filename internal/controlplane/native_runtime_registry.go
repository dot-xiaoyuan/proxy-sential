package controlplane

func (s *Server) nativeRuntime(id string) (NativeActionRuntime, bool) {
	if s.nativeActionsMu == nil {
		runtime, ok := s.nativeActions[id]
		return runtime, ok
	}
	s.nativeActionsMu.RLock()
	defer s.nativeActionsMu.RUnlock()
	runtime, ok := s.nativeActions[id]
	return runtime, ok
}

// Epochs fence slow credential reads from an earlier configuration. In-flight
// network requests already handed to an SDK are not cancelled by this registry.
func (s *Server) invalidateNativeRuntime(id string) uint64 {
	if s.nativeActionsMu != nil {
		s.nativeActionsMu.Lock()
		defer s.nativeActionsMu.Unlock()
	}
	if s.nativeActionEpochs == nil {
		s.nativeActionEpochs = map[string]uint64{}
	}
	s.nativeActionEpochs[id]++
	delete(s.nativeActions, id)
	return s.nativeActionEpochs[id]
}

func (s *Server) setNativeRuntimeAtEpoch(id string, epoch uint64, runtime *NativeActionRuntime) bool {
	if s.nativeActionsMu != nil {
		s.nativeActionsMu.Lock()
		defer s.nativeActionsMu.Unlock()
	}
	if s.nativeActionEpochs[id] != epoch {
		return false
	}
	if s.nativeActionEpochs == nil {
		s.nativeActionEpochs = map[string]uint64{}
	}
	s.nativeActionEpochs[id]++ // Consume this refresh lease exactly once.
	if runtime != nil {
		if s.nativeActions == nil {
			s.nativeActions = map[string]NativeActionRuntime{}
		}
		s.nativeActions[id] = *runtime
	}
	return true
}

func (s *Server) setNativeRuntime(id string, runtime NativeActionRuntime) {
	if s.nativeActionsMu != nil {
		s.nativeActionsMu.Lock()
		defer s.nativeActionsMu.Unlock()
	}
	if s.nativeActionEpochs == nil {
		s.nativeActionEpochs = map[string]uint64{}
	}
	s.nativeActionEpochs[id]++
	if s.nativeActions == nil {
		s.nativeActions = map[string]NativeActionRuntime{}
	}
	s.nativeActions[id] = runtime
}

func (s *Server) nativeRuntimeSnapshot() map[string]NativeActionRuntime {
	if s.nativeActionsMu == nil {
		result := make(map[string]NativeActionRuntime, len(s.nativeActions))
		for id, runtime := range s.nativeActions {
			result[id] = runtime
		}
		return result
	}
	s.nativeActionsMu.RLock()
	defer s.nativeActionsMu.RUnlock()
	result := make(map[string]NativeActionRuntime, len(s.nativeActions))
	for id, runtime := range s.nativeActions {
		result[id] = runtime
	}
	return result
}
