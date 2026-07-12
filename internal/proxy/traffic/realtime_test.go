package traffic

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"
)

func TestRealtimeManagerSamplesOnlyAfterSubscribeAndEmitsDelta(t *testing.T) {
	reads := make(chan trafficCounters, 2)
	readCalls := 0
	mgr := NewRealtimeManager(RealtimeOptions{
		Interval: 10 * time.Millisecond,
		ReaderForDevice: func(deviceID string) (realtimeCounterReader, error) {
			if deviceID != "dev-a" {
				t.Fatalf("deviceID=%q want dev-a", deviceID)
			}
			return realtimeCounterReader{
				DeviceID:  "dev-a",
				Interface: "wwan0",
				ReadCounters: func(context.Context) (trafficCounters, error) {
					readCalls++
					return <-reads, nil
				},
			}, nil
		},
	})

	if readCalls != 0 {
		t.Fatalf("readCalls=%d before subscribe, want 0", readCalls)
	}

	reads <- trafficCounters{RXBytes: 1000, TXBytes: 500}
	reads <- trafficCounters{RXBytes: 1600, TXBytes: 800}
	ch, unsubscribe := mgr.Subscribe(context.Background(), "dev-a")
	defer unsubscribe()

	first := receiveRealtimeSnapshot(t, ch)
	if first.Status != RealtimeStatusWaitingSample || first.RXDeltaBytes != 0 || first.TXDeltaBytes != 0 {
		t.Fatalf("first snapshot=%+v want waiting baseline", first)
	}

	second := receiveRealtimeSnapshot(t, ch)
	if second.Status != RealtimeStatusOK {
		t.Fatalf("second status=%q want %q snapshot=%+v", second.Status, RealtimeStatusOK, second)
	}
	if second.RXDeltaBytes != 600 || second.TXDeltaBytes != 300 {
		t.Fatalf("second deltas rx=%d tx=%d want rx=600 tx=300", second.RXDeltaBytes, second.TXDeltaBytes)
	}
	if second.RXBPS <= 0 || second.TXBPS <= 0 {
		t.Fatalf("second rates rx_bps=%d tx_bps=%d want positive", second.RXBPS, second.TXBPS)
	}
}

func TestRealtimeManagerMarksCounterRollbackAsReset(t *testing.T) {
	reads := make(chan trafficCounters, 2)
	mgr := NewRealtimeManager(RealtimeOptions{
		Interval: 10 * time.Millisecond,
		ReaderForDevice: func(string) (realtimeCounterReader, error) {
			return realtimeCounterReader{
				DeviceID:  "dev-a",
				Interface: "wwan0",
				ReadCounters: func(context.Context) (trafficCounters, error) {
					return <-reads, nil
				},
			}, nil
		},
	})

	reads <- trafficCounters{RXBytes: 1000, TXBytes: 500}
	reads <- trafficCounters{RXBytes: 100, TXBytes: 50}
	ch, unsubscribe := mgr.Subscribe(context.Background(), "dev-a")
	defer unsubscribe()

	_ = receiveRealtimeSnapshot(t, ch)
	second := receiveRealtimeSnapshot(t, ch)
	if second.Status != RealtimeStatusReset {
		t.Fatalf("status=%q want %q snapshot=%+v", second.Status, RealtimeStatusReset, second)
	}
	if second.RXDeltaBytes != 0 || second.TXDeltaBytes != 0 || second.RXBPS != 0 || second.TXBPS != 0 {
		t.Fatalf("reset snapshot=%+v want zero deltas/rates", second)
	}
}

func TestRealtimeSnapshotJSONDoesNotIncludeRollingWindowFields(t *testing.T) {
	payload, err := json.Marshal(RealtimeSnapshot{
		DeviceID:     "dev-a",
		Source:       trafficCounterSourceQMIWDS,
		Status:       RealtimeStatusOK,
		RXDeltaBytes: 100,
		TXDeltaBytes: 50,
	})
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(payload, &fields); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}
	for _, field := range []string{"rx_window_bytes", "tx_window_bytes", "window_seconds"} {
		if _, ok := fields[field]; ok {
			t.Fatalf("field %q should not be present in realtime snapshot JSON: %s", field, payload)
		}
	}
}

func TestRealtimeManagerRestartsBaselineAfterReadError(t *testing.T) {
	type readResult struct {
		counters trafficCounters
		err      error
	}

	reads := make(chan readResult, 3)
	mgr := NewRealtimeManager(RealtimeOptions{
		Interval: 10 * time.Millisecond,
		ReaderForDevice: func(string) (realtimeCounterReader, error) {
			return realtimeCounterReader{
				DeviceID:  "dev-a",
				Interface: "wwan0",
				ReadCounters: func(context.Context) (trafficCounters, error) {
					result := <-reads
					return result.counters, result.err
				},
			}, nil
		},
	})

	reads <- readResult{counters: trafficCounters{RXBytes: 1000, TXBytes: 500}}
	ch, unsubscribe := mgr.Subscribe(context.Background(), "dev-a")
	defer unsubscribe()
	_ = receiveRealtimeSnapshot(t, ch)

	reads <- readResult{err: errors.New("qmi read failed")}
	errSnap := receiveRealtimeSnapshot(t, ch)
	if errSnap.Status != RealtimeStatusError {
		t.Fatalf("status=%q want %q snapshot=%+v", errSnap.Status, RealtimeStatusError, errSnap)
	}

	reads <- readResult{counters: trafficCounters{RXBytes: 1600, TXBytes: 800}}
	afterError := receiveRealtimeSnapshot(t, ch)
	if afterError.Status != RealtimeStatusWaitingSample {
		t.Fatalf("status=%q want %q snapshot=%+v", afterError.Status, RealtimeStatusWaitingSample, afterError)
	}
	if afterError.RXDeltaBytes != 0 || afterError.TXDeltaBytes != 0 {
		t.Fatalf("after error snapshot=%+v want no delta bytes", afterError)
	}
}

func receiveRealtimeSnapshot(t *testing.T, ch <-chan RealtimeSnapshot) RealtimeSnapshot {
	t.Helper()
	select {
	case snap := <-ch:
		return snap
	case <-time.After(200 * time.Millisecond):
		t.Fatal("timed out waiting for realtime traffic snapshot")
		return RealtimeSnapshot{}
	}
}
