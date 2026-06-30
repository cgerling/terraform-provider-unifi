package utils

import (
	"errors"
	"strings"

	"github.com/filipowm/go-unifi/v2/unifi"
)

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
