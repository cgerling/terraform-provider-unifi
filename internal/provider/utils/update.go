package utils

import (
	"errors"
	"strings"

	"github.com/filipowm/go-unifi/v2/unifi"
)

// IsEmptyResponseError reports whether an error returned by a go-unifi update*
// function indicates a successful-but-empty PUT response from the controller
// (HTTP 200, {"meta":{"rc":"ok"},"data":[]}). This happens when the controller
// considers the update a no-op — i.e. nothing actually changed.
//
// go-unifi v1.9.2 returned unifi.ErrNotFound for this case; v2.0.1 returns
// fmt.Errorf("unexpected response: expected 1 <Type>, got 0"). This helper
// matches both forms so callers don't need to know which version is in use.
func IsEmptyResponseError(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, unifi.ErrNotFound) {
		return true
	}
	msg := err.Error()
	return strings.HasPrefix(msg, "unexpected response: expected 1 ") &&
		strings.HasSuffix(msg, ", got 0")
}

// ReReadOnUpdateNotFound works around a go-unifi behavior shared by every
// generated update* function: after a successful PUT they apply a
// `len(respBody.Data) != 1` guard, so a successful-but-empty response
// (HTTP 200, {"meta":{"rc":"ok"},"data":[]}) — which UniFi controllers return
// when the update is a no-op — is converted into an error even though the
// resource is intact. SDKv2 Update handlers that surface that verbatim via
// diag.FromErr therefore fail on a successful update.
//
// Given the (object, error) pair returned by an update* call and a reRead closure
// (typically c.Get<Resource>(ctx, site, id)), it returns:
//   - (updated, true, nil)  when the update succeeded normally;
//   - (reRead,  true, nil)  when the update returned an empty-response error but
//     the object still exists (the no-op case) — the re-read object is returned
//     so that controller-side normalization is preserved;
//   - (zero,    false, nil) when the update returned an empty-response error AND
//     the re-read also returns ErrNotFound — i.e. the object was genuinely
//     deleted out-of-band; the caller should clear state (d.SetId("")) and
//     recreate;
//   - (zero,    false, err) for any other error, from either the update or the
//     re-read.
func ReReadOnUpdateNotFound[T any](updated T, updateErr error, reRead func() (T, error)) (result T, found bool, err error) {
	if updateErr == nil {
		return updated, true, nil
	}
	var zero T
	if !IsEmptyResponseError(updateErr) {
		return zero, false, updateErr
	}
	obj, reReadErr := reRead()
	if errors.Is(reReadErr, unifi.ErrNotFound) {
		return zero, false, nil
	}
	if reReadErr != nil {
		return zero, false, reReadErr
	}
	return obj, true, nil
}
