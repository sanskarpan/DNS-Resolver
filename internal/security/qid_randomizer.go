package security

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"sync"
)

type QueryIDRandomizer struct {
	mu       sync.Mutex
	inFlight map[uint16]struct{}
}

func NewQueryIDRandomizer() *QueryIDRandomizer {
	return &QueryIDRandomizer{inFlight: make(map[uint16]struct{})}
}

func (q *QueryIDRandomizer) Acquire() (uint16, error) {
	q.mu.Lock()
	defer q.mu.Unlock()

	for i := 0; i < 1024; i++ {
		id, err := randomUint16()
		if err != nil {
			return 0, err
		}
		if _, ok := q.inFlight[id]; ok {
			continue
		}
		q.inFlight[id] = struct{}{}
		return id, nil
	}
	return 0, fmt.Errorf("unable to allocate unique query id")
}

func (q *QueryIDRandomizer) Release(id uint16) {
	q.mu.Lock()
	defer q.mu.Unlock()
	delete(q.inFlight, id)
}

func randomUint16() (uint16, error) {
	var b [2]byte
	if _, err := rand.Read(b[:]); err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint16(b[:]), nil
}
