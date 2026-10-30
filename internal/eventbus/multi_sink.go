package eventbus

import "context"

// MultiSink lets one projected batch reach independent shadow sinks. A failure
// in any sink fails the batch, so the Kafka offset is not committed and all
// idempotent sinks are replayed.
type MultiSink []ReceiptSink

func NewMultiSink(sinks ...ReceiptSink) MultiSink {
	out := make(MultiSink, 0, len(sinks))
	for _, sink := range sinks {
		if sink != nil {
			out = append(out, sink)
		}
	}
	return out
}

func (s MultiSink) WriteReceipts(ctx context.Context, receipts []Receipt) error {
	for _, sink := range s {
		if err := sink.WriteReceipts(ctx, receipts); err != nil {
			return err
		}
	}
	return nil
}
