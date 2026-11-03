package imscore

import (
	"context"
	"strings"
	"testing"
)

func TestProtectedFailurePreservesStatusAndCancellation(t *testing.T) {
	err := newProtectedPhaseError(protectedPhaseStageResponse, &registrarAttemptError{statusCode: 403, reason: "forbidden"})
	safe := newSafeRegisterFailure(err)
	if !strings.Contains(safe.Error(), "status=403") || !strings.Contains(safe.Error(), "stage=response") {
		t.Fatal("protected response lost its status or stage")
	}
	err = newProtectedPhaseError(protectedPhaseStageRead, context.Canceled)
	if !strings.Contains(newSafeRegisterFailure(err).Error(), "result=canceled") {
		t.Fatal("protected cancellation was reclassified as authentication failure")
	}
}
