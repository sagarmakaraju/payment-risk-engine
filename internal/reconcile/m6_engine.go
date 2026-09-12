package reconcile

import (
	"fmt"
	"sort"
	"sync"
	"time"

	"fs2601/internal/edge"
	"fs2601/internal/ledger"
)

// DeficitRecord captures an offline transaction that exceeded available balance on replay
type DeficitRecord struct {
	TxID            string    `json:"tx_id"`
	AccountID       string    `json:"account_id"`
	MerchantID      string    `json:"merchant_id"`
	Amount          int64     `json:"amount"`
	AvailableOnCore int64     `json:"available_on_core"`
	DeficitAmount   int64     `json:"deficit_amount"`
	FlaggedForAlert bool      `json:"flagged_for_alert"`
	CreatedAt       time.Time `json:"created_at"`
	Reason          string    `json:"reason"`
}

// ReconciliationReport summarizes the results of the post-partition replay
type ReconciliationReport struct {
	TotalProcessed        int             `json:"total_processed"`
	SuccessfulCount       int             `json:"successful_count"`
	DeficitCount          int             `json:"deficit_count"`
	DuplicateCount        int             `json:"duplicate_count"`
	TotalAmountReconciled int64           `json:"total_amount_reconciled"`
	TotalDeficitAmount    int64           `json:"total_deficit_amount"`
	DeficitRecords        []DeficitRecord `json:"deficit_records,omitempty"`
	StartedAt             time.Time       `json:"started_at"`
	CompletedAt           time.Time       `json:"completed_at"`
}

// Reconciler executes deterministic replay of offline transactions onto the core ledger
type Reconciler struct {
	mu                sync.Mutex
	ledger            *ledger.ConservingLedger
	seenHashes        map[string]bool
	deficitLogs       []DeficitRecord
	useDeficitReserve bool // Feature 5: Automated Merchant Deficit Liability Allocation
}

// NewReconciler creates a reconciliation engine connected to the core ledger
func NewReconciler(coreLedger *ledger.ConservingLedger) *Reconciler {
	return &Reconciler{
		ledger:            coreLedger,
		seenHashes:        make(map[string]bool),
		deficitLogs:       make([]DeficitRecord, 0),
		useDeficitReserve: false, // Default false for backward compatibility with legacy deficit tests
	}
}

// SetUseDeficitReserve configures whether deficits are absorbed by ACC_MERCHANT_DEFICIT_RESERVE (Feature 5)
func (r *Reconciler) SetUseDeficitReserve(enabled bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.useDeficitReserve = enabled
}

// CompareVectorClocks compares two vector clocks for causal precedence (Feature 4)
// Returns -1 if a < b (a precedes b), 1 if b < a (b precedes a), 0 if concurrent
func CompareVectorClocks(va, vb map[string]uint64) int {
	if len(va) == 0 && len(vb) == 0 {
		return 0
	}
	aLeB := true
	bLeA := true
	allKeys := make(map[string]bool)
	for k := range va {
		allKeys[k] = true
	}
	for k := range vb {
		allKeys[k] = true
	}

	for k := range allKeys {
		ca := va[k]
		cb := vb[k]
		if ca > cb {
			aLeB = false
		}
		if cb > ca {
			bLeA = false
		}
	}

	if aLeB && !bLeA {
		return -1 // a causally precedes b
	}
	if bLeA && !aLeB {
		return 1 // b causally precedes a
	}
	return 0 // concurrent / incomparable
}

// SortTransactionsVectorClock deterministically sorts queued transactions using Vector Clocks and monotonic sequences
func SortTransactionsVectorClock(queued []edge.QueuedTransaction) {
	sort.SliceStable(queued, func(i, j int) bool {
		cmp := CompareVectorClocks(queued[i].VectorClock, queued[j].VectorClock)
		if cmp != 0 {
			return cmp < 0
		}
		// Tie-breaker 1: Monotonic terminal sequence number (Feature 4)
		if queued[i].SeqNo != queued[j].SeqNo {
			return queued[i].SeqNo < queued[j].SeqNo
		}
		// Tie-breaker 2: Legacy SequenceNum
		if queued[i].SequenceNum != queued[j].SequenceNum {
			return queued[i].SequenceNum < queued[j].SequenceNum
		}
		// Tie-breaker 3: TerminalID lexicographically
		if queued[i].TerminalID != queued[j].TerminalID {
			return queued[i].TerminalID < queued[j].TerminalID
		}
		// Tie-breaker 4: ClientTimestamp
		if queued[i].ClientTimestamp != queued[j].ClientTimestamp {
			return queued[i].ClientTimestamp < queued[j].ClientTimestamp
		}
		// Tie-breaker 5: TxID
		return queued[i].TxID < queued[j].TxID
	})
}

// Replay deterministic batch of queued transactions from the edge store
func (r *Reconciler) Replay(store *edge.WALStore) (*ReconciliationReport, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	startTime := time.Now().UTC()
	queued := store.ReadAllPending()

	// 1. Sort deterministically using Vector Clocks & monotonic sequences (Feature 4)
	SortTransactionsVectorClock(queued)

	report := &ReconciliationReport{
		TotalProcessed: len(queued),
		StartedAt:      startTime,
		DeficitRecords: make([]DeficitRecord, 0),
	}

	for _, tx := range queued {
		// 2. Global deduplication check via cryptographic transaction hash
		hash := tx.PayloadHash
		if hash == "" {
			hash = tx.ComputeHash()
		}

		if r.seenHashes[hash] {
			report.DuplicateCount++
			store.UpdateStatus(tx.TxID, "DUPLICATE")
			continue
		}
		r.seenHashes[hash] = true

		// 3. Inspect account available balance on Core Ledger
		accSnapshot, err := r.ledger.GetAccount(tx.AccountID)
		if err != nil {
			accSnapshot = ledger.AccountSnapshot{
				ID:               tx.AccountID,
				AvailableBalance: 0,
				OnlineAvailable:  0,
				OfflineAllowance: 0,
			}
		}

		// Feature 1: Check if covered by dedicated OfflineAllowance
		if accSnapshot.OfflineAllowance >= tx.Amount {
			if err := r.ledger.CommitOfflineAllowance(tx.AccountID, tx.MerchantID, tx.Amount, tx.TxID); err == nil {
				report.SuccessfulCount++
				report.TotalAmountReconciled += tx.Amount
				store.UpdateStatus(tx.TxID, "RECONCILED")
				continue
			}
		}

		// Check if covered by OnlineAvailable
		if accSnapshot.OnlineAvailable >= tx.Amount {
			commitErr := r.ledger.DirectCommit(tx.AccountID, tx.MerchantID, tx.Amount, tx.TxID)
			if commitErr == nil {
				report.SuccessfulCount++
				report.TotalAmountReconciled += tx.Amount
				store.UpdateStatus(tx.TxID, "RECONCILED")
				continue
			}
		}

		// 4. Overdraw / Deficit Handling
		if r.useDeficitReserve {
			// Feature 5: Automated Merchant Deficit Liability Allocation
			// Never drop customer balance below zero!
			customerCovered := accSnapshot.OnlineAvailable
			if customerCovered < 0 {
				customerCovered = 0
			}
			if customerCovered > tx.Amount {
				customerCovered = tx.Amount
			}
			uncoveredDelta := tx.Amount - customerCovered

			if customerCovered > 0 {
				_ = r.ledger.DirectCommit(tx.AccountID, tx.MerchantID, customerCovered, tx.TxID+"-USER")
			}

			if uncoveredDelta > 0 {
				_ = r.ledger.DebitDeficitReserve(tx.MerchantID, uncoveredDelta, tx.TxID+"-RESERVE")
			}

			deficitEntry := DeficitRecord{
				TxID:            tx.TxID,
				AccountID:       tx.AccountID,
				MerchantID:      tx.MerchantID,
				Amount:          tx.Amount,
				AvailableOnCore: accSnapshot.OnlineAvailable,
				DeficitAmount:   uncoveredDelta,
				FlaggedForAlert: true,
				CreatedAt:       time.Now().UTC(),
				Reason:          "RECON_DEFICIT_CHARGED_TO_RESERVE",
			}

			r.deficitLogs = append(r.deficitLogs, deficitEntry)
			report.DeficitRecords = append(report.DeficitRecords, deficitEntry)
			report.DeficitCount++
			report.TotalDeficitAmount += tx.Amount
			store.UpdateStatus(tx.TxID, "DEFICIT")
		} else {
			// Legacy Deficit Mode: Direct overdraft debit
			deficitAmount := tx.Amount - accSnapshot.OnlineAvailable
			if deficitAmount < 0 {
				deficitAmount = tx.Amount
			}

			deficitEntry := DeficitRecord{
				TxID:            tx.TxID,
				AccountID:       tx.AccountID,
				MerchantID:      tx.MerchantID,
				Amount:          tx.Amount,
				AvailableOnCore: accSnapshot.OnlineAvailable,
				DeficitAmount:   deficitAmount,
				FlaggedForAlert: true,
				CreatedAt:       time.Now().UTC(),
				Reason:          fmt.Sprintf("Insufficient available funds on core (available: %d cents, required: %d cents)", accSnapshot.OnlineAvailable, tx.Amount),
			}

			r.deficitLogs = append(r.deficitLogs, deficitEntry)
			report.DeficitRecords = append(report.DeficitRecords, deficitEntry)
			report.DeficitCount++
			report.TotalDeficitAmount += tx.Amount

			_ = r.ledger.RecordDeficit(tx.AccountID, tx.MerchantID, tx.Amount, tx.TxID)
			store.UpdateStatus(tx.TxID, "DEFICIT")
		}
	}

	report.CompletedAt = time.Now().UTC()
	return report, nil
}

// GetDeficitLogs returns all flagged deficit logs
func (r *Reconciler) GetDeficitLogs() []DeficitRecord {
	r.mu.Lock()
	defer r.mu.Unlock()
	copied := make([]DeficitRecord, len(r.deficitLogs))
	copy(copied, r.deficitLogs)
	return copied
}