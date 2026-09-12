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
	mu           sync.Mutex
	ledger       *ledger.ConservingLedger
	seenHashes   map[string]bool
	deficitLogs  []DeficitRecord
}

// NewReconciler creates a reconciliation engine connected to the core ledger
func NewReconciler(coreLedger *ledger.ConservingLedger) *Reconciler {
	return &Reconciler{
		ledger:      coreLedger,
		seenHashes:  make(map[string]bool),
		deficitLogs: make([]DeficitRecord, 0),
	}
}

// Replay deterministic batch of queued transactions from the edge store
func (r *Reconciler) Replay(store *edge.WALStore) (*ReconciliationReport, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	startTime := time.Now().UTC()
	queued := store.ReadAllPending()

	// 1. Sort deterministically by ClientTimestamp -> SequenceNum -> TxID
	sort.Slice(queued, func(i, j int) bool {
		if queued[i].ClientTimestamp != queued[j].ClientTimestamp {
			return queued[i].ClientTimestamp < queued[j].ClientTimestamp
		}
		if queued[i].SequenceNum != queued[j].SequenceNum {
			return queued[i].SequenceNum < queued[j].SequenceNum
		}
		return queued[i].TxID < queued[j].TxID
	})

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
			// If account was deleted or not found, register it
			accSnapshot = ledger.AccountSnapshot{
				ID:               tx.AccountID,
				AvailableBalance: 0,
			}
		}

		if accSnapshot.AvailableBalance >= tx.Amount {
			// Normal reconciliation: Commit directly to destination/merchant
			commitErr := r.ledger.DirectCommit(tx.AccountID, tx.MerchantID, tx.Amount, tx.TxID)
			if commitErr == nil {
				report.SuccessfulCount++
				report.TotalAmountReconciled += tx.Amount
				store.UpdateStatus(tx.TxID, "RECONCILED")
				continue
			}
		}

		// 4. Overdraw / Deficit Case:
		// Account has insufficient funds on core ledger (e.g. drained concurrently during partition)
		deficitAmount := tx.Amount - accSnapshot.AvailableBalance
		if deficitAmount < 0 {
			deficitAmount = tx.Amount
		}

		deficitEntry := DeficitRecord{
			TxID:            tx.TxID,
			AccountID:       tx.AccountID,
			MerchantID:      tx.MerchantID,
			Amount:          tx.Amount,
			AvailableOnCore: accSnapshot.AvailableBalance,
			DeficitAmount:   deficitAmount,
			FlaggedForAlert: true,
			CreatedAt:       time.Now().UTC(),
			Reason:          fmt.Sprintf("Insufficient available funds on core (available: %d cents, required: %d cents)", accSnapshot.AvailableBalance, tx.Amount),
		}

		r.deficitLogs = append(r.deficitLogs, deficitEntry)
		report.DeficitRecords = append(report.DeficitRecords, deficitEntry)
		report.DeficitCount++
		report.TotalDeficitAmount += tx.Amount

		// Record deficit on core ledger preserving double-entry conservation
		_ = r.ledger.RecordDeficit(tx.AccountID, tx.MerchantID, tx.Amount, tx.TxID)
		store.UpdateStatus(tx.TxID, "DEFICIT")
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
