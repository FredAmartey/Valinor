package activity

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/valinor-ai/valinor/internal/platform/database"
)

type LoggerConfig struct {
	BufferSize    int
	BatchSize     int
	FlushInterval time.Duration
}

type AsyncLogger struct {
	ch     chan Event
	store  *Store
	db     database.Querier
	cfg    LoggerConfig
	wg     sync.WaitGroup
	cancel context.CancelFunc
}

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
	logger := &AsyncLogger{
		ch:     make(chan Event, cfg.BufferSize),
		store:  store,
		db:     db,
		cfg:    cfg,
		cancel: cancel,
	}
	logger.wg.Add(1)
	go logger.worker(ctx)
	return logger
}

func (l *AsyncLogger) Log(_ context.Context, event Event) {
	select {
	case l.ch <- event:
	default:
		slog.Warn("activity buffer full, dropping event", "kind", event.Kind, "status", event.Status)
	}
}

func (l *AsyncLogger) Close() error {
	l.cancel()
	l.wg.Wait()
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
			batch = append(batch, l.drainAll()...)
			l.flush(batch)
			return
		case event := <-l.ch:
			batch = append(batch, event)
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
		slog.Error("activity flush failed", "error", err, "count", len(events))
	}
}

func (l *AsyncLogger) drainAll() []Event {
	var events []Event
	for {
		select {
		case event := <-l.ch:
			events = append(events, event)
		default:
			return events
		}
	}
}
