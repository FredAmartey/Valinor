package audit

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockDB implements database.Querier for testing.
type mockDB struct {
	mu    sync.Mutex
	count int
}

func (m *mockDB) Exec(_ context.Context, _ string, _ ...any) (pgconn.CommandTag, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.count++
	return pgconn.NewCommandTag("INSERT 0 1"), nil
}

func (m *mockDB) Query(_ context.Context, _ string, _ ...any) (pgx.Rows, error) {
	return nil, nil
}

func (m *mockDB) QueryRow(_ context.Context, _ string, _ ...any) pgx.Row {
	return nil
}

func (m *mockDB) insertCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.count
}

func TestAsyncLogger_FlushesOnInterval(t *testing.T) {
	db := &mockDB{}
	cfg := LoggerConfig{
		BufferSize:    100,
		BatchSize:     10,
		FlushInterval: 50 * time.Millisecond,
	}

	logger := NewAsyncLogger(db, NewStore(), cfg)

	tenantID := uuid.New()
	logger.Log(context.Background(), Event{
		TenantID: tenantID,
		Action:   "test.action",
		Source:   "test",
	})

	// Wait for flush interval
	time.Sleep(150 * time.Millisecond)

	require.NoError(t, logger.Close())
	assert.GreaterOrEqual(t, db.insertCount(), 1)
}

func TestAsyncLogger_FlushesOnBatchSize(t *testing.T) {
	db := &mockDB{}
	cfg := LoggerConfig{
		BufferSize:    100,
		BatchSize:     3,
		FlushInterval: 10 * time.Second,
	}

	logger := NewAsyncLogger(db, NewStore(), cfg)

	tenantID := uuid.New()
	for i := 0; i < 3; i++ {
		logger.Log(context.Background(), Event{
			TenantID: tenantID,
			Action:   "test.action",
			Source:   "test",
		})
	}

	time.Sleep(100 * time.Millisecond)

	require.NoError(t, logger.Close())
	assert.GreaterOrEqual(t, db.insertCount(), 1)
}

func TestAsyncLogger_DropsWhenBufferFull(t *testing.T) {
	db := &mockDB{}
	cfg := LoggerConfig{
		BufferSize:    2,
		BatchSize:     100,
		FlushInterval: 10 * time.Second,
	}

	logger := NewAsyncLogger(db, NewStore(), cfg)

	tenantID := uuid.New()
	// Send more events than buffer can hold
	for i := 0; i < 10; i++ {
		logger.Log(context.Background(), Event{
			TenantID: tenantID,
			Action:   "test.action",
			Source:   "test",
		})
	}

	require.NoError(t, logger.Close())
	// Should not panic — events are dropped gracefully
}
