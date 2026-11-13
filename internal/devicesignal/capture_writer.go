package devicesignal

// boundedCaptureWriter keeps disk serialization off the packet receive loop.
// Its queue holds a fixed number of detached buckets; when it fills, submit
// blocks so the kernel's packet counters continue to expose the overload.
type boundedCaptureWriter[T any] struct {
	queue chan T
	done  chan struct{}
	err   error
}

func newBoundedCaptureWriter[T any](capacity int, write func(T) error, finish func() error) *boundedCaptureWriter[T] {
	w := &boundedCaptureWriter[T]{queue: make(chan T, capacity), done: make(chan struct{})}
	go func() {
		defer close(w.done)
		for item := range w.queue {
			if err := write(item); err != nil {
				w.err = err
				return
			}
		}
		w.err = finish()
	}()
	return w
}

func (w *boundedCaptureWriter[T]) submit(item T) error {
	select {
	case <-w.done:
		return w.err
	default:
	}
	select {
	case w.queue <- item:
		return nil
	case <-w.done:
		return w.err
	}
}

func (w *boundedCaptureWriter[T]) closeAndWait() error {
	close(w.queue)
	<-w.done
	return w.err
}

func (w *boundedCaptureWriter[T]) failed() error {
	select {
	case <-w.done:
		return w.err
	default:
		return nil
	}
}
