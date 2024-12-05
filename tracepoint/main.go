package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go bpf trace.c -- -I../headers

const mapKey uint32 = 0

// AllocationInfo represents a memory allocation event from the kernel
type AllocationInfo struct {
	// Pid is the process ID that made the allocation
	Pid uint32
	// Comm is the command name (process name) that made the allocation, fixed at 16 bytes
	Comm [16]byte
	// Order is the page allocation order (2^Order * PAGE_SIZE bytes)
	Order uint32
	// Timestamp is when the allocation occurred, in nanoseconds
	Timestamp uint64
}

func main() {
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %v", err)
	}
	defer objs.Close()

	pid := uint32(os.Getpid())
	if err := objs.PidMap.Put(uint32(0), pid); err != nil {
		log.Fatalf("storing pid: %v", err)
	}

	kp, err := link.Tracepoint("kmem", "kmem_cache_alloc", objs.KmemCacheAlloc, nil)
	if err != nil {
		log.Fatalf("opening tracepoint: %s", err)
	}
	defer kp.Close()

	kp2, err := link.Tracepoint("kmem", "mm_page_alloc", objs.MmPageAlloc, nil)
	if err != nil {
		log.Fatalf("opening tracepoint: %s", err)
	}
	defer kp2.Close()

	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	// Create channel to listen for interrupt signals.
	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)

	// Create a ring buffer to receive events
	rb, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		log.Fatalf("opening ringbuf: %s", err)
	}
	defer rb.Close()

	go func() {
		var event AllocationInfo
		for {
			record, err := rb.Read()
			if err != nil {
				if errors.Is(err, ringbuf.ErrClosed) {
					return
				}
				log.Printf("error reading from ring buffer: %s", err)
				continue
			}

			if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &event); err != nil {
				log.Printf("error parsing event: %s", err)
				continue
			}

			comm := strings.TrimRight(string(event.Comm[:]), "\x00")
			log.Printf("Page alloc: pid=%d comm=%s order=%d",
				event.Pid, comm, event.Order)
		}
	}()

	log.Println("Waiting for events.. Press Ctrl-C to exit")
	for {
		select {
		case <-ticker.C:
			var cacheBytes, pageCount, pageBytes uint64

			if err := objs.CountingMap.Lookup(uint32(0), &cacheBytes); err != nil {
				log.Fatalf("reading cache bytes: %v", err)
			}
			if err := objs.CountingMap.Lookup(uint32(1), &pageCount); err != nil {
				log.Fatalf("reading page count: %v", err)
			}
			if err := objs.CountingMap.Lookup(uint32(2), &pageBytes); err != nil {
				log.Fatalf("reading page bytes: %v", err)
			}

			log.Printf("Cache bytes: %v, Page allocations: %v, Page bytes: %v",
				cacheBytes, pageCount, pageBytes)
		case <-stopper:
			log.Println("Received signal, exiting..")
			return
		}
	}
}
