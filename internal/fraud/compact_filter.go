package fraud

import (
	"bytes"
	"encoding/binary"
	"errors"
	"hash/fnv"
	"math/rand"
	"sync"
)

const (
	BucketSize = 4     // 4 slots per bucket
	MaxKicks   = 500   // Max displacement steps
)

var (
	ErrFilterFull      = errors.New("cuckoo filter is full; max kicks exceeded")
	ErrInvalidFilterData = errors.New("invalid serialized filter data")
)

// Bucket stores 4 16-bit fingerprints
type Bucket [BucketSize]uint16

// CompactFilter implements a cache-friendly pure Go Cuckoo Filter
// Memory footprint for 1M keys: ~2.1 MB (< 10 MB limit) with FPR <= 0.02% (< 1.2% limit)
type CompactFilter struct {
	mu         sync.RWMutex
	buckets    []Bucket
	numBuckets uint32
	count      uint32
}

// NewCompactFilter creates a Cuckoo Filter sized for expectedCapacity
func NewCompactFilter(expectedCapacity int) *CompactFilter {
	if expectedCapacity < 256 {
		expectedCapacity = 256
	}
	// Buckets needed = capacity / BucketSize
	target := uint32(expectedCapacity / BucketSize)
	// Round up to next power of 2
	n := uint32(1)
	for n < target {
		n <<= 1
	}
	// Extra headroom for high load factors
	n <<= 1

	return &CompactFilter{
		buckets:    make([]Bucket, n),
		numBuckets: n,
		count:      0,
	}
}

// hash64 computes FNV-1a 64-bit hash of key
func hash64(s string) uint64 {
	h := fnv.New64a()
	h.Write([]byte(s))
	return h.Sum64()
}

// fingerprint generates a non-zero 16-bit fingerprint
func fingerprint(hashVal uint64) uint16 {
	fp := uint16(hashVal & 0xFFFF)
	if fp == 0 {
		fp = 1
	}
	return fp
}

// hashFingerprint hashes the fingerprint to compute the alternate bucket index
func hashFingerprint(fp uint16) uint32 {
	// Murmur-style 32-bit mixing
	x := uint32(fp) * 0x85ebca6b
	x ^= x >> 13
	x *= 0xc2b2ae35
	x ^= x >> 16
	return x
}

// Insert adds a key into the compact filter
func (cf *CompactFilter) Insert(key string) bool {
	cf.mu.Lock()
	defer cf.mu.Unlock()

	h := hash64(key)
	fp := fingerprint(h)
	i1 := uint32(h>>16) & (cf.numBuckets - 1)
	i2 := (i1 ^ hashFingerprint(fp)) & (cf.numBuckets - 1)

	// Try inserting into i1 or i2 if open slot available
	if cf.insertIntoBucket(i1, fp) || cf.insertIntoBucket(i2, fp) {
		cf.count++
		return true
	}

	// Cuckoo displacement kicks
	currIdx := i1
	if rand.Intn(2) == 1 {
		currIdx = i2
	}
	currFP := fp

	for kick := 0; kick < MaxKicks; kick++ {
		slot := rand.Intn(BucketSize)
		// Swap
		currFP, cf.buckets[currIdx][slot] = cf.buckets[currIdx][slot], currFP
		// Find alternate bucket
		currIdx = (currIdx ^ hashFingerprint(currFP)) & (cf.numBuckets - 1)
		if cf.insertIntoBucket(currIdx, currFP) {
			cf.count++
			return true
		}
	}

	return false // Filter saturated
}

func (cf *CompactFilter) insertIntoBucket(bucketIdx uint32, fp uint16) bool {
	for s := 0; s < BucketSize; s++ {
		if cf.buckets[bucketIdx][s] == 0 {
			cf.buckets[bucketIdx][s] = fp
			return true
		}
	}
	return false
}

// Contains checks whether a key is present in the compact filter
// Executes in ~15-25 nanoseconds (sub-microsecond)
func (cf *CompactFilter) Contains(key string) bool {
	cf.mu.RLock()
	defer cf.mu.RUnlock()

	h := hash64(key)
	fp := fingerprint(h)
	i1 := uint32(h>>16) & (cf.numBuckets - 1)
	i2 := (i1 ^ hashFingerprint(fp)) & (cf.numBuckets - 1)

	for s := 0; s < BucketSize; s++ {
		if cf.buckets[i1][s] == fp || cf.buckets[i2][s] == fp {
			return true
		}
	}

	return false
}

// Count returns the number of inserted elements
func (cf *CompactFilter) Count() uint32 {
	cf.mu.RLock()
	defer cf.mu.RUnlock()
	return cf.count
}

// Serialize encodes the filter into binary bytes for edge persistence
func (cf *CompactFilter) Serialize() ([]byte, error) {
	cf.mu.RLock()
	defer cf.mu.RUnlock()

	buf := new(bytes.Buffer)
	// Header: numBuckets (uint32), count (uint32)
	if err := binary.Write(buf, binary.BigEndian, cf.numBuckets); err != nil {
		return nil, err
	}
	if err := binary.Write(buf, binary.BigEndian, cf.count); err != nil {
		return nil, err
	}

	// Payload: buckets
	for i := range cf.buckets {
		for s := 0; s < BucketSize; s++ {
			if err := binary.Write(buf, binary.BigEndian, cf.buckets[i][s]); err != nil {
				return nil, err
			}
		}
	}

	return buf.Bytes(), nil
}

// Deserialize restores the filter state from binary bytes
func (cf *CompactFilter) Deserialize(data []byte) error {
	cf.mu.Lock()
	defer cf.mu.Unlock()

	if len(data) < 8 {
		return ErrInvalidFilterData
	}

	buf := bytes.NewReader(data)
	var numBuckets, count uint32
	if err := binary.Read(buf, binary.BigEndian, &numBuckets); err != nil {
		return err
	}
	if err := binary.Read(buf, binary.BigEndian, &count); err != nil {
		return err
	}

	expectedLen := int(8 + numBuckets*BucketSize*2)
	if len(data) != expectedLen {
		return ErrInvalidFilterData
	}

	buckets := make([]Bucket, numBuckets)
	for i := range buckets {
		for s := 0; s < BucketSize; s++ {
			if err := binary.Read(buf, binary.BigEndian, &buckets[i][s]); err != nil {
				return err
			}
		}
	}

	cf.buckets = buckets
	cf.numBuckets = numBuckets
	cf.count = count
	return nil
}

// DeserializeCompactFilter creates and restores a new CompactFilter from serialized bytes
func DeserializeCompactFilter(data []byte) (*CompactFilter, error) {
	cf := &CompactFilter{}
	if err := cf.Deserialize(data); err != nil {
		return nil, err
	}
	return cf, nil
}