package device

import "testing"

func TestWorkerAcceptsRuntimeUIMIndicationOnlyAfterStartupReady(t *testing.T) {
	w := &Worker{ID: "dev-qmi"}

	if workerAcceptsRuntimeUIMIndication(w) {
		t.Fatal("worker accepted runtime UIM indication before startup ready")
	}

	w.uimIndicationsReady.Store(true)

	if !workerAcceptsRuntimeUIMIndication(w) {
		t.Fatal("worker rejected runtime UIM indication after startup ready")
	}
}

func TestWorkerAcceptsRuntimeUIMIndicationRejectsNilWorker(t *testing.T) {
	if workerAcceptsRuntimeUIMIndication(nil) {
		t.Fatal("nil worker accepted runtime UIM indication")
	}
}
