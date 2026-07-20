package utils

import (
	"errors"
	"regexp"

	"github.com/filipowm/go-unifi/v2/unifi"
)

// ReReadOnUpdateNotFound works around a go-unifi v1.9.3 defect shared by every
// generated update* function: after a successful PUT they apply a
// `len(respBody.Data) != 1 -> unifi.ErrNotFound` guard, so a successful-but-empty
// response (HTTP 200, {"meta":{"rc":"ok"},"data":[]}) — which some UniFi
// controllers return on an update — is converted into unifi.ErrNotFound even
// though the change WAS applied. SDKv2 Update handlers that surface that verbatim
// via diag.FromErr therefore fail with "Error: not found" on a successful update.
// See issue #98.
//
// Given the (object, error) pair returned by an update* call and a reRead closure
// (typically c.Get<Resource>(ctx, site, id)), it returns:
//   - (updated, true, nil)  when the update succeeded normally;
//   - (reRead,  true, nil)  when the update returned ErrNotFound but the object
//     still exists (the spurious case) — the re-read object is returned so that
//     controller-side normalization is preserved;
//   - (zero,    false, nil) when the update returned ErrNotFound AND the re-read
//     also returns ErrNotFound — i.e. the object was genuinely deleted
//     out-of-band; the caller should clear state (d.SetId("")) and recreate;
//   - (zero,    false, err) for any other error, from either the update or the
//     re-read.
//
// A genuine controller 404 surfaces as a *unifi.ServerError from the response
// error handler before the len() guard is reached, so "update -> ErrNotFound"
// never by itself means "deleted"; only the re-read's own ErrNotFound does. That
// is why the re-read GET is required rather than echoing the request struct.
//
// go-unifi v2 no longer maps the empty echo to unifi.ErrNotFound; its generated
// update* functions instead return a formatted `unexpected response: expected 1
// <Type>, got 0` error (UniFi 10.x returns an empty data array on a successful
// networkconf update). emptyUpdateEcho matches that shape so it is handled
// identically to the historical ErrNotFound case: re-read to recover state.
var emptyUpdateEcho = regexp.MustCompile(`unexpected response: expected 1 \w+, got 0\b`)

// isSpuriousUpdateNotFound reports whether an update error is the "successful but
// empty echo" false negative — either the v1.9.x ErrNotFound mapping or the v2
// formatted error — that must be resolved by re-reading rather than surfaced.
func isSpuriousUpdateNotFound(err error) bool {
	return errors.Is(err, unifi.ErrNotFound) || emptyUpdateEcho.MatchString(err.Error())
}

func ReReadOnUpdateNotFound[T any](updated T, updateErr error, reRead func() (T, error)) (result T, found bool, err error) {
	if updateErr == nil {
		return updated, true, nil
	}
	var zero T
	if !isSpuriousUpdateNotFound(updateErr) {
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
