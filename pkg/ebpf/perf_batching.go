package ebpf

import (
	"fmt"
	"time"
	"unsafe"

	"github.com/DataDog/datadog-agent/pkg/network"
	bpflib "github.com/iovisor/gobpf/bcc"
)

const (
	TCPCloseBatchSize = 5
	maxNumberBatches  = 1024
)

type batchState struct {
	offset  int64
	updated int64
}

// PerfBatchManager is reponsbile for two things:
//
// * Keeping track of the state of each batch object we read off the perf ring;
//
// * Detecting idle batch objects (this might happen in hosts with a very low connection churn);
//
// The motivation is to impose an upper limit on how long a TCP close connection
// event remains stored in the eBPF map before being processed by the NetworkAgent.
type PerfBatchManager struct {
	// eBPF
	module   *bpflib.Module
	batchMap *bpflib.Map

	// stateByCPUCore contains the state of each batch.
	// The slice is indexed by the CPU core number.
	stateByCPUCore []batchState

	// lastIdleFlush represents the last time we flushed idle batches
	lastIdleFlush time.Time

	// maxIdleInterval represents the maximum time (in nanoseconds)
	// a batch can remain idle in the eBPF map
	maxIdleInterval int64
}

// NewPerfBatchManager returns a new `PerfBatchManager` and initializes the
// eBPF map that holds the tcp_close batch objects.
func NewPerfBatchManager(module *bpflip.Module, batchMap *bpflib.Map) *PerfBatchManager {
	if module == nil {
		return nil, fmt.Errorf("module is nil")
	}
	if batchMap == nil {
		return nil, fmt.Errorf("batchMap is nil")
	}

	for i := 0; i < maxNumberBatches; i++ {
		b := new(batch)
		b.cpu = uint16(i)
		module.UpdateElement(batchMap, unsafe.Pointer(&i), unsafe.Pointer(b), 0)
	}

	return &PerfBatchManager{module: module, batchMap: batchMap}, nil
}

// ProcessBatch extracts from a `batch` object all connections that haven't been processed yet
// and also keeps track of the last time this CPU core flushed a batch to the perf ring.
// Notice this method is called every time we read a (full) batch off the perf ring.
func (p *PerfBatchManager) ProcessBatch(b *batch, now time.Time) []network.ConnectionStats {
	if b.cpu >= len(stateByCPUCore) {
		return
	}

	lastOffset := p.stateByCPUCore[b.cpu].offset
	p.stateByCPUCore[b.cpu].updated = now.UnixNano()
	p.stateByCPUCore[b.cpu].offset = 0

	return ExtractStatsFromBatch(b, lastOffset, TCPCloseBatchSize)
}

// GetIdleConns return all connections that have been "stuck" in idle batches
// for more than `idleInterval`
func (p *PerfBatchManager) GetIdleConns(now time.Time) []network.ConnectionStats {
	if now.Sub(p.lastIdleFlush) < p.idleInterval {
		return nil
	}

	var idle []network.ConnectionStats
	nowTS := now.UnixNano()
	batch := new(batch)
	for i := 0; i < len(p.stateByCPUCore); i++ {
		state := p.stateByCPUCore[i]

		// batch has been updated recently
		if (nowTS - state.lastFlush) < maxIdleInterval {
			continue
		}

		// we have an idle batch, so let's retrieve its data from eBPF
		err := p.module.LookupElement(p.batchMap, unsafe.Pointer(&i), unsafe.Pointer(batch))
		if err != nil {
			continue
		}

		p.stateByCPUCore[i].updated = now

		// batch is empty || batch doesn't have new entries
		if batch.pos == 0 || batch.pos == state.offset+1 {
			continue
		}

		idle = ExtractBatchInto(idle, batch, state.offset+1, batch.pos)
		p.stateByCPUCore[i].offset = batch.pos - 1
	}
}

// ExtractBatchInto extract network.ConnectionStats objects from the given `batch`
// The `start` (inclusive) and `end` (exclusive) arguments represent the offsets
// which we want to extract.
func ExtractBatchInto(buffer []network.ConnectionStats, b *batch, start, end int) []network.ConnectionStats {
	if start >= end || end > TCPCloseBatchSize {
		return nil
	}

	var (
		connSize = unsafe.Sizeof(b.c0)
		current  = uintptr(b) + start*connSize
	)

	for i := start; i < end; i++ {
		ct := TCPConn(*(*C.tcp_conn_t)(unsafe.Pointer(current)))
		tup := ConnTuple(ct.tup)
		cst := ConnStatsWithTimestamp(ct.conn_stats)
		tst := TCPStats(ct.tcp_stats)

		buffer = append(buffer, connStats(&tup, &cst, &tst))
		current += connSize
	}

	return buffer
}
