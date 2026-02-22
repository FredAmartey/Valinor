package audit

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/valinor-ai/valinor/internal/platform/database"
)

// LoggerConfig configures the async audit logger.
type LoggerConfig struct {
	BufferSize    int
	BatchSize     int
	FlushInterval time.Duration
}

// AsyncLogger implements Logger with a buffered channel and background worker.
type AsyncLogger struct {
	ch     chan Event
	store  *Store
	db     database.Querier
	cfg    LoggerConfig
	wg     sync.WaitGroup
	cancel context.CancelFunc
}

// NewAsyncLogger creates and starts an async audit logger.
func NewAsyncLogger(db database.Querier, store *Store, cfg LoggerConfig) *AsyncLogger {
	if cfg.BufferSize <= 0 {
		cfg.BufferSize = 4096
	}
	if cfg.BatchSize <= 0 {
		cfg.BatchSize = 100
	}
	if cfg.FlushInterval <= 0 {
		cfg.FlushInterval = 500 * time.Millisecond
	}

	ctx, cancel := context.WithCancel(context.Background())
	l := &AsyncLogger{
		ch:     make(chan Event, cfg.BufferSize),
		store:  store,
		db:     db,
		cfg:    cfg,
		cancel: cancel,
	}

	l.wg.Add(1)
	go l.worker(ctx)

	return l
}

// Log enqueues an audit event. Never blocks the caller — drops if buffer full.
func (l *AsyncLogger) Log(_ context.Context, event Event) {
	select {
	case l.ch <- event:
	default:
		slog.Warn("audit buffer full, dropping event", "action", event.Action)
	}
}

// Close flushes remaining events and stops the worker.
func (l *AsyncLogger) Close() error {
	l.cancel()
	l.wg.Wait()
	// Drain any remaining events
	l.flush(l.drainAll())
	return nil
}

func (l *AsyncLogger) worker(ctx context.Context) {
	defer l.wg.Done()

	ticker := time.NewTicker(l.cfg.FlushInterval)
	defer ticker.Stop()

	var batch []Event

	for {
		select {
		case <-ctx.Done():
			// Drain channel before exiting
			batch = append(batch, l.drainAll()...)
			l.flush(batch)
			return

		case e := <-l.ch:
			batch = append(batch, e)
			if len(batch) >= l.cfg.BatchSize {
				l.flush(batch)
				batch = nil
			}

		case <-ticker.C:
			if len(batch) > 0 {
				l.flush(batch)
				batch = nil
			}
		}
	}
}

func (l *AsyncLogger) flush(events []Event) {
	if len(events) == 0 {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := l.store.InsertBatch(ctx, l.db, events); err != nil {
		slog.Error("audit flush failed", "error", err, "count", len(events))
	}
}

func (l *AsyncLogger) drainAll() []Event {
	var events []Event
	for {
		select {
		case e := <-l.ch:
			events = append(events, e)
		default:
			return events
		}
	}
}
