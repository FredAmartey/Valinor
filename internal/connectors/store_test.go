package connectors_test

import (
	"context"
	"errors"
	"testing"

	"github.com/valinor-ai/valinor/internal/connectors"
)

func TestNewStore(t *testing.T) {
	store := connectors.NewStore()
	if store == nil {
		t.Fatal("NewStore returned nil")
	}
}

func TestCreateValidation(t *testing.T) {
	store := connectors.NewStore()

	t.Run("empty name returns error", func(t *testing.T) {
		_, err := store.Create(context.Background(), nil, "", "mcp", "https://example.com", nil, nil, nil)
		if !errors.Is(err, connectors.ErrNameEmpty) {
			t.Fatalf("expected ErrNameEmpty, got %v", err)
		}
	})

	t.Run("empty endpoint returns error", func(t *testing.T) {
		_, err := store.Create(context.Background(), nil, "test", "mcp", "", nil, nil, nil)
		if !errors.Is(err, connectors.ErrEndpointEmpty) {
			t.Fatalf("expected ErrEndpointEmpty, got %v", err)
		}
	})
}
