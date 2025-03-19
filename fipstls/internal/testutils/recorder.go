package testutils

import (
	"io"
	"math"
	"sort"
	"sync"
	"testing"
	"time"
)

type recorder interface {
	RecordProgress(streamID int, msgCount int, isSender bool)
	io.Closer
}

type emptyRecorder struct{}

func (emptyRecorder) RecordProgress(streamID int, msgCount int, isSender bool) {}
func (emptyRecorder) Close() error                                             { return nil }

// StreamEvent represents a progress update from a single stream.
type StreamEvent struct {
	StreamID int
	Interval int
	IsSender bool // distinguish between send/receive progress
}

// ProgressRecorder tracks and reports progress across multiple concurrent streams.
// It collects progress events from individual streams and periodically reports
// aggregated progress statistics.
type ProgressRecorder struct {
	t              testing.TB
	eventChan      chan StreamEvent
	numStreams     int
	numMessages    int
	sampleSize     int
	printTicker    *time.Ticker
	currentStats   map[int]map[int]bool // map[interval]map[streamID]received
	streamProgress sync.Map             // map[int]int - streamID -> lastRecordedInterval
	done           chan struct{}
}

// NewProgressRecorder creates a new ProgressRecorder that tracks progress
// for the specified number of streams and interval size.
//
// Parameters:
//   - numStreams: total number of streams to track
//   - intervalSize: number of messages that constitute one interval
func NewProgressRecorder(t testing.TB, enableProgRecorder bool, numStreams, numMessages,
	sampleSize int, runPeriod time.Duration) recorder {
	if !enableProgRecorder {
		return &emptyRecorder{}
	}
	pr := &ProgressRecorder{
		t:            t,
		eventChan:    make(chan StreamEvent, numStreams*2),
		numStreams:   numStreams,
		numMessages:  numMessages,
		sampleSize:   sampleSize,
		currentStats: make(map[int]map[int]bool),
		printTicker:  time.NewTicker(runPeriod),
		done:         make(chan struct{}),
	}
	go pr.run()
	return pr
}

// RecordProgress records a progress update for a specific stream.
// It only records the progress if the stream has reached a new interval.
func (pr *ProgressRecorder) RecordProgress(streamID int, msgCount int, isSender bool) {
	interval := msgCount / pr.sampleSize

	lastInterval, exists := pr.streamProgress.Load(streamID)
	if !exists || interval > lastInterval.(int) {
		pr.streamProgress.Store(streamID, interval)
		pr.eventChan <- StreamEvent{
			StreamID: streamID,
			Interval: interval,
			IsSender: isSender,
		}
	}
}

// run is the main event loop that processes incoming stream events and triggers
// periodic progress updates. It runs in its own goroutine until Close() is called.
func (pr *ProgressRecorder) run() {
	for {
		select {
		case event := <-pr.eventChan:
			if _, exists := pr.currentStats[event.Interval]; !exists {
				pr.currentStats[event.Interval] = make(map[int]bool)
			}
			pr.currentStats[event.Interval][event.StreamID] = true

		case <-pr.printTicker.C:
			pr.printProgress()

		case <-pr.done:
			pr.printTicker.Stop()
			return
		}
	}
}

// printProgress prints the current progress for all active intervals.
// It displays the percentage of streams that have completed each interval
// and cleans up completed intervals.
func (pr *ProgressRecorder) printProgress() {
	// Sort intervals for ordered printing
	var intervals []int
	for interval := range pr.currentStats {
		intervals = append(intervals, interval)
	}
	sort.Ints(intervals)

	for _, interval := range intervals {
		streams := pr.currentStats[interval]
		count := len(streams)
		if count == pr.numStreams {
			msgsDone := float64((interval+1)*pr.sampleSize) / float64(pr.numMessages) * 100
			msgsLeft := math.Round(((1 - (msgsDone / 100)) * float64(pr.numMessages)))
			pr.t.Logf("interval%2d: %2.0f%% per-stream messages processed. %7d messages left.\n",
				interval,
				msgsDone,
				int(msgsLeft),
			)
			delete(pr.currentStats, interval)
		} else {
			percentage := float64(count) / float64(pr.numStreams) * 100
			pr.t.Logf("interval%2d: %2.0f%% of streams done processing...\n", interval, percentage)
		}
	}
}

func (pr *ProgressRecorder) Close() error {
	close(pr.done)
	return nil
}
