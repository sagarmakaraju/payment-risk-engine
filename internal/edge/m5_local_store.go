package edge

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"os"
	"sync"
)

var (
	WALMagicBytes         = []byte{0x57, 0x41, 0x4C, 0x31} // "WAL1"
	ErrCorruptFrame       = errors.New("corrupt WAL record frame")
	ErrCRCMismatch        = errors.New("CRC32 payload checksum mismatch")
	ErrTxAlreadyExists    = errors.New("transaction already exists in WAL")
)

// QueuedTransaction represents an edge-persisted transaction awaiting reconciliation
type QueuedTransaction struct {
	TxID            string `json:"tx_id"`
	ClientTimestamp int64  `json:"client_timestamp"`
	SequenceNum     int64  `json:"sequence_num"`
	TokenID         string `json:"token_id"`
	AccountID       string `json:"account_id"`
	MerchantID      string `json:"merchant_id"`
	TerminalID      string `json:"terminal_id"`
	Amount          int64  `json:"amount"` // in cents
	Signature       string `json:"signature"`
	Status          string `json:"status"` // PENDING, RECONCILED, DEFICIT
	PayloadHash     string `json:"payload_hash"`
}

// ComputeHash computes the SHA-256 deduplication hash for the transaction
func (tx *QueuedTransaction) ComputeHash() string {
	raw := fmt.Sprintf("%s:%d:%d:%s:%s:%s:%d",
		tx.TxID, tx.ClientTimestamp, tx.SequenceNum, tx.TokenID, tx.AccountID, tx.MerchantID, tx.Amount)
	h := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(h[:])
}

// WALStore provides crash-resilient append-only persistence with CRC32 verification and fsync
type WALStore struct {
	mu        sync.RWMutex
	filePath  string
	file      *os.File
	txMap     map[string]QueuedTransaction // TxID -> QueuedTransaction
	order     []string                     // TxID insertion order
	seqNumber uint64
}

// NewWALStore opens or creates a crash-resilient WAL log file and recovers existing state
func NewWALStore(filePath string) (*WALStore, error) {
	file, err := os.OpenFile(filePath, os.O_CREATE|os.O_RDWR, 0644)
	if err != nil {
		return nil, fmt.Errorf("failed to open WAL file %s: %w", filePath, err)
	}

	store := &WALStore{
		filePath: filePath,
		file:     file,
		txMap:    make(map[string]QueuedTransaction),
		order:    make([]string, 0),
	}

	// Recover existing records and handle crash recovery
	if err := store.recover(); err != nil {
		file.Close()
		return nil, fmt.Errorf("crash recovery failed on %s: %w", filePath, err)
	}

	return store, nil
}

// recover scans the WAL sequentially, validating CRC32 frames and restoring state
func (s *WALStore) recover() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, err := s.file.Seek(0, io.SeekStart); err != nil {
		return err
	}

	headerBuf := make([]byte, 20) // 4 (magic) + 8 (seq) + 4 (len) + 4 (crc)
	validOffset := int64(0)

	for {
		readOffset, _ := s.file.Seek(0, io.SeekCurrent)
		n, err := io.ReadFull(s.file, headerBuf)
		if err == io.EOF || err == io.ErrUnexpectedEOF {
			break // End of stream
		}
		if err != nil {
			return err
		}
		if n < 20 {
			break
		}

		// Validate magic bytes
		if headerBuf[0] != WALMagicBytes[0] || headerBuf[1] != WALMagicBytes[1] ||
			headerBuf[2] != WALMagicBytes[2] || headerBuf[3] != WALMagicBytes[3] {
			// Found corrupted frame; truncate at last known valid offset
			break
		}

		seq := binary.BigEndian.Uint64(headerBuf[4:12])
		length := binary.BigEndian.Uint32(headerBuf[12:16])
		expectedCRC := binary.BigEndian.Uint32(headerBuf[16:20])

		payload := make([]byte, length)
		pn, perr := io.ReadFull(s.file, payload)
		if perr != nil || uint32(pn) != length {
			// Incomplete write during crash; truncate
			break
		}

		// Verify CRC32 checksum
		calcCRC := crc32.ChecksumIEEE(payload)
		if calcCRC != expectedCRC {
			// Corrupt payload; truncate
			break
		}

		var tx QueuedTransaction
		if err := json.Unmarshal(payload, &tx); err != nil {
			break
		}

		s.txMap[tx.TxID] = tx
		s.order = append(s.order, tx.TxID)
		if seq > s.seqNumber {
			s.seqNumber = seq
		}

		validOffset = readOffset + int64(20+length)
	}

	// Truncate any incomplete or damaged trailer to guarantee crash resilience
	if err := s.file.Truncate(validOffset); err != nil {
		return err
	}
	if _, err := s.file.Seek(validOffset, io.SeekStart); err != nil {
		return err
	}

	return nil
}

// Append synchronously writes and fsyncs a transaction to the WAL
func (s *WALStore) Append(tx QueuedTransaction) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.txMap[tx.TxID]; exists {
		return ErrTxAlreadyExists
	}

	if tx.PayloadHash == "" {
		tx.PayloadHash = tx.ComputeHash()
	}

	payload, err := json.Marshal(tx)
	if err != nil {
		return fmt.Errorf("failed to marshal transaction: %w", err)
	}

	s.seqNumber++
	header := make([]byte, 20)
	copy(header[0:4], WALMagicBytes)
	binary.BigEndian.PutUint64(header[4:12], s.seqNumber)
	binary.BigEndian.PutUint32(header[12:16], uint32(len(payload)))
	binary.BigEndian.PutUint32(header[16:20], crc32.ChecksumIEEE(payload))

	// Write frame header + payload
	if _, err := s.file.Write(header); err != nil {
		return fmt.Errorf("failed to write WAL frame header: %w", err)
	}
	if _, err := s.file.Write(payload); err != nil {
		return fmt.Errorf("failed to write WAL frame payload: %w", err)
	}

	// Immediate fsync for crash durability
	if err := s.file.Sync(); err != nil {
		return fmt.Errorf("failed to sync WAL to disk: %w", err)
	}

	s.txMap[tx.TxID] = tx
	s.order = append(s.order, tx.TxID)
	return nil
}

// ReadAllPending returns all transactions currently pending reconciliation
func (s *WALStore) ReadAllPending() []QueuedTransaction {
	s.mu.RLock()
	defer s.mu.RUnlock()

	pending := make([]QueuedTransaction, 0, len(s.txMap))
	for _, txID := range s.order {
		tx := s.txMap[txID]
		if tx.Status == "PENDING" || tx.Status == "" {
			pending = append(pending, tx)
		}
	}
	return pending
}

// ReadAll returns all transactions in the WAL
func (s *WALStore) ReadAll() []QueuedTransaction {
	s.mu.RLock()
	defer s.mu.RUnlock()

	all := make([]QueuedTransaction, 0, len(s.order))
	for _, txID := range s.order {
		all = append(all, s.txMap[txID])
	}
	return all
}

// UpdateStatus updates the transaction status in memory
func (s *WALStore) UpdateStatus(txID string, newStatus string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if tx, exists := s.txMap[txID]; exists {
		tx.Status = newStatus
		s.txMap[txID] = tx
	}
}

// Close flushes and closes the WAL store
func (s *WALStore) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.file != nil {
		_ = s.file.Sync()
		return s.file.Close()
	}
	return nil
}
