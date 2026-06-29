package utils

import (
	"errors"
	"fmt"
	"testing"

	"github.com/filipowm/go-unifi/v2/unifi"
	"github.com/stretchr/testify/assert"
)

func TestIsEmptyResponseError(t *testing.T) {
	t.Run("nil error", func(t *testing.T) {
		assert.False(t, IsEmptyResponseError(nil))
	})

	t.Run("unrelated error", func(t *testing.T) {
		assert.False(t, IsEmptyResponseError(errors.New("something else")))
	})

	t.Run("ErrNotFound (go-unifi v1 style)", func(t *testing.T) {
		assert.True(t, IsEmptyResponseError(unifi.ErrNotFound))
	})

	t.Run("wrapped ErrNotFound", func(t *testing.T) {
		assert.True(t, IsEmptyResponseError(fmt.Errorf("outer: %w", unifi.ErrNotFound)))
	})

	t.Run("unexpected response got 0 (go-unifi v2 style)", func(t *testing.T) {
		assert.True(t, IsEmptyResponseError(fmt.Errorf("unexpected response: expected 1 Network, got 0")))
	})

	t.Run("unexpected response got 0 - different type name", func(t *testing.T) {
		assert.True(t, IsEmptyResponseError(fmt.Errorf("unexpected response: expected 1 WLAN, got 0")))
	})

	t.Run("unexpected response got 2 - not empty", func(t *testing.T) {
		assert.False(t, IsEmptyResponseError(fmt.Errorf("unexpected response: expected 1 Network, got 2")))
	})
}

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

	t.Run("update returns non-empty-response error - propagated, no re-read", func(t *testing.T) {
		sentinel := errors.New("boom")
		reReadCalled := false
		got, found, err := ReReadOnUpdateNotFound((*obj)(nil), sentinel, func() (*obj, error) {
			reReadCalled = true
			return nil, nil
		})
		assert.ErrorIs(t, err, sentinel)
		assert.False(t, found)
		assert.Nil(t, got)
		assert.False(t, reReadCalled, "re-read must not run for non-empty-response errors")
	})

	t.Run("update returns ErrNotFound, re-read succeeds - returns re-read object", func(t *testing.T) {
		reReadObj := &obj{name: "from-reread"}
		got, found, err := ReReadOnUpdateNotFound((*obj)(nil), unifi.ErrNotFound, func() (*obj, error) {
			return reReadObj, nil
		})
		assert.NoError(t, err)
		assert.True(t, found)
		assert.Same(t, reReadObj, got)
	})

	t.Run("update returns v2 unexpected response, re-read succeeds - returns re-read object", func(t *testing.T) {
		reReadObj := &obj{name: "from-reread"}
		v2Err := fmt.Errorf("unexpected response: expected 1 Network, got 0")
		got, found, err := ReReadOnUpdateNotFound((*obj)(nil), v2Err, func() (*obj, error) {
			return reReadObj, nil
		})
		assert.NoError(t, err)
		assert.True(t, found)
		assert.Same(t, reReadObj, got)
	})

	t.Run("update returns empty-response error, re-read also ErrNotFound - genuinely deleted", func(t *testing.T) {
		got, found, err := ReReadOnUpdateNotFound((*obj)(nil), unifi.ErrNotFound, func() (*obj, error) {
			return nil, unifi.ErrNotFound
		})
		assert.NoError(t, err)
		assert.False(t, found)
		assert.Nil(t, got)
	})

	t.Run("update returns empty-response error, re-read fails - propagates re-read error", func(t *testing.T) {
		reReadErr := errors.New("network down")
		got, found, err := ReReadOnUpdateNotFound((*obj)(nil), unifi.ErrNotFound, func() (*obj, error) {
			return nil, reReadErr
		})
		assert.ErrorIs(t, err, reReadErr)
		assert.False(t, found)
		assert.Nil(t, got)
	})
}
