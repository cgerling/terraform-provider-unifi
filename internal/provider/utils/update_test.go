package utils

import (
	"errors"
	"fmt"
	"testing"

	"github.com/filipowm/go-unifi/v2/unifi"
	"github.com/stretchr/testify/assert"
)

// TestReReadOnUpdateNotFound covers the issue #98 workaround shared by every SDKv2
// Update handler: go-unifi v1.9.2 turns a successful-but-empty PUT into
// unifi.ErrNotFound, so the helper must re-read instead of surfacing the spurious
// error, while still distinguishing a genuine out-of-band deletion and propagating
// real errors.
func TestReReadOnUpdateNotFound(t *testing.T) {
	type obj struct{ name string }

	t.Run("update succeeds - returns update result, no re-read", func(t *testing.T) {
		updated := &obj{name: "from-update"}
		reReadCalled := false
		got, found, err := ReReadOnUpdateNotFound(updated, nil, func() (*obj, error) {
			reReadCalled = true
			return nil, nil
		})
		assert.NoError(t, err)
		assert.True(t, found)
		assert.Same(t, updated, got)
		assert.False(t, reReadCalled, "re-read must not run when update succeeds")
	})

	t.Run("update returns non-NotFound error - propagated, no re-read", func(t *testing.T) {
		sentinel := errors.New("boom")
		reReadCalled := false
		got, found, err := ReReadOnUpdateNotFound((*obj)(nil), sentinel, func() (*obj, error) {
			reReadCalled = true
			return nil, nil
		})
		assert.ErrorIs(t, err, sentinel)
		assert.False(t, found)
		assert.Nil(t, got)
		assert.False(t, reReadCalled, "re-read must not run for a real error")
	})

	t.Run("spurious ErrNotFound but object exists - returns re-read result", func(t *testing.T) {
		reRead := &obj{name: "from-reread"}
		got, found, err := ReReadOnUpdateNotFound((*obj)(nil), unifi.ErrNotFound, func() (*obj, error) {
			return reRead, nil
		})
		assert.NoError(t, err)
		assert.True(t, found)
		assert.Same(t, reRead, got, "re-read object (with controller normalization) must be returned")
	})

	t.Run("update and re-read both ErrNotFound - genuine deletion", func(t *testing.T) {
		got, found, err := ReReadOnUpdateNotFound((*obj)(nil), unifi.ErrNotFound, func() (*obj, error) {
			return nil, unifi.ErrNotFound
		})
		assert.NoError(t, err, "genuine deletion must not error so the caller can clear state")
		assert.False(t, found)
		assert.Nil(t, got)
	})

	t.Run("spurious ErrNotFound but re-read fails - propagates re-read error", func(t *testing.T) {
		sentinel := errors.New("read failed")
		got, found, err := ReReadOnUpdateNotFound((*obj)(nil), unifi.ErrNotFound, func() (*obj, error) {
			return nil, sentinel
		})
		assert.ErrorIs(t, err, sentinel)
		assert.False(t, found)
		assert.Nil(t, got)
	})

	t.Run("v2 empty-echo error but object exists - re-reads and returns result", func(t *testing.T) {
		// go-unifi v2's post-PUT guard on UniFi 10.x: successful write, empty data echo.
		emptyEcho := fmt.Errorf("unexpected response: expected 1 Network, got %d", 0)
		reRead := &obj{name: "from-reread"}
		reReadCalled := false
		got, found, err := ReReadOnUpdateNotFound((*obj)(nil), emptyEcho, func() (*obj, error) {
			reReadCalled = true
			return reRead, nil
		})
		assert.NoError(t, err)
		assert.True(t, found)
		assert.Same(t, reRead, got)
		assert.True(t, reReadCalled, "v2 empty-echo must trigger a re-read")
	})

	t.Run("unexpected non-zero count is a real error - propagated, no re-read", func(t *testing.T) {
		// "got 2" is a genuine response anomaly, not the empty-echo false negative,
		// so it must not be masked by a re-read.
		anomaly := fmt.Errorf("unexpected response: expected 1 Network, got %d", 2)
		reReadCalled := false
		got, found, err := ReReadOnUpdateNotFound((*obj)(nil), anomaly, func() (*obj, error) {
			reReadCalled = true
			return nil, nil
		})
		assert.ErrorIs(t, err, anomaly)
		assert.False(t, found)
		assert.Nil(t, got)
		assert.False(t, reReadCalled, "a non-empty unexpected count must not be masked by a re-read")
	})
}
