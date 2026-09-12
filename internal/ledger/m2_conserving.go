package ledger

import (
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"
)

var (
	ErrAccountNotFound    = errors.New("account not found")
	ErrInsufficientFunds  = errors.New("insufficient available balance")
	ErrInvalidAmount      = errors.New("amount must be strictly positive")
	ErrReservationNotFound= errors.New("reservation not found")
	ErrHoldMismatch       = errors.New("reserved balance less than hold commit amount")
)

// EntryType represents the nature of a double-entry transaction
type EntryType string

const (
	EntryReserve EntryType = "RESERVE"
	EntryCommit  EntryType = "COMMIT"
	EntryRelease EntryType = "RELEASE"
	EntryDeficit EntryType = "DEFICIT"
)

// LedgerEntry represents an immutable double-entry ledger audit record
type LedgerEntry struct {
	EntryID     int64     `json:"entry_id"`
	TxID        string    `json:"tx_id"`
	Type        EntryType `json:"type"`
	DebitAcc    string    `json:"debit_account"`
	CreditAcc   string    `json:"credit_account"`
	Amount      int64     `json:"amount"` // in cents
	Timestamp   time.Time `json:"timestamp"`
	Description string    `json:"description"`
}

// Account represents a financial entity maintaining conserved balances
type Account struct {
	mu               sync.RWMutex
	ID               string    `json:"id"`
	AvailableBalance int64     `json:"available_balance"` // in cents
	ReservedBalance  int64     `json:"reserved_balance"`  // in cents
	Version          int64     `json:"version"`
	UpdatedAt        time.Time `json:"updated_at"`
}

// AccountSnapshot provides a point-in-time copy of account balances
type AccountSnapshot struct {
	ID               string    `json:"id"`
	AvailableBalance int64     `json:"available_balance"`
	ReservedBalance  int64     `json:"reserved_balance"`
	TotalBalance     int64     `json:"total_balance"`
	Version          int64     `json:"version"`
	UpdatedAt        time.Time `json:"updated_at"`
}

// Reservation tracks an active fund hold
type Reservation struct {
	ReservationID string    `json:"reservation_id"`
	AccountID     string    `json:"account_id"`
	Amount        int64     `json:"amount"`
	CreatedAt     time.Time `json:"created_at"`
}

// ConservingLedger manages accounts and double-entry consistency
type ConservingLedger struct {
	accountsLock sync.RWMutex
	accounts     map[string]*Account

	resLock      sync.RWMutex
	reservations map[string]*Reservation

	entriesLock  sync.RWMutex
	entries      []LedgerEntry
	entryCounter int64

	// System accounts
	EscrowAccountID   string
	ClearingAccountID string
}

// NewConservingLedger initializes the ledger with designated system accounts
func NewConservingLedger() *ConservingLedger {
	l := &ConservingLedger{
		accounts:          make(map[string]*Account),
		reservations:      make(map[string]*Reservation),
		entries:           make([]LedgerEntry, 0, 10000),
		EscrowAccountID:   "SYSTEM_ESCROW",
		ClearingAccountID: "SYSTEM_CLEARING",
	}

	// Create system accounts
	l.CreateAccount(l.EscrowAccountID, 0)
	l.CreateAccount(l.ClearingAccountID, 0)
	return l
}

// CreateAccount registers a new account with an initial balance
func (l *ConservingLedger) CreateAccount(id string, initialBalance int64) *Account {
	l.accountsLock.Lock()
	defer l.accountsLock.Unlock()

	if acc, exists := l.accounts[id]; exists {
		return acc
	}

	acc := &Account{
		ID:               id,
		AvailableBalance: initialBalance,
		ReservedBalance:  0,
		Version:          1,
		UpdatedAt:        time.Now().UTC(),
	}
	l.accounts[id] = acc
	return acc
}

// GetAccount returns a thread-safe snapshot of the account
func (l *ConservingLedger) GetAccount(id string) (AccountSnapshot, error) {
	l.accountsLock.RLock()
	acc, exists := l.accounts[id]
	l.accountsLock.RUnlock()

	if !exists {
		return AccountSnapshot{}, ErrAccountNotFound
	}

	acc.mu.RLock()
	defer acc.mu.RUnlock()

	return AccountSnapshot{
		ID:               acc.ID,
		AvailableBalance: acc.AvailableBalance,
		ReservedBalance:  acc.ReservedBalance,
		TotalBalance:     acc.AvailableBalance + acc.ReservedBalance,
		Version:          acc.Version,
		UpdatedAt:        acc.UpdatedAt,
	}, nil
}

// ReserveFunds atomically checks and reserves available balance
// Enforces invariant: AvailableBalance >= amount. Never allows blind decrements.
func (l *ConservingLedger) ReserveFunds(accountID string, amount int64, txID string) (string, error) {
	if amount <= 0 {
		return "", ErrInvalidAmount
	}

	l.accountsLock.RLock()
	acc, exists := l.accounts[accountID]
	l.accountsLock.RUnlock()

	if !exists {
		return "", ErrAccountNotFound
	}

	acc.mu.Lock()
	defer acc.mu.Unlock()

	// Hard Gate: Financial correctness check
	if acc.AvailableBalance < amount {
		return "", ErrInsufficientFunds
	}

	// Atomically move from Available to Reserved
	acc.AvailableBalance -= amount
	acc.ReservedBalance += amount
	acc.Version++
	acc.UpdatedAt = time.Now().UTC()

	resID := fmt.Sprintf("RES-%s-%d", txID, time.Now().UnixNano())

	l.resLock.Lock()
	l.reservations[resID] = &Reservation{
		ReservationID: resID,
		AccountID:     accountID,
		Amount:        amount,
		CreatedAt:     time.Now().UTC(),
	}
	l.resLock.Unlock()

	// Double-entry record: Debit User, Credit Escrow
	l.appendEntry(LedgerEntry{
		TxID:        txID,
		Type:        EntryReserve,
		DebitAcc:    accountID,
		CreditAcc:   l.EscrowAccountID,
		Amount:      amount,
		Timestamp:   time.Now().UTC(),
		Description: fmt.Sprintf("Funds reserved under %s", resID),
	})

	return resID, nil
}

// CommitHold finalizes a reservation and settles it to destination account
func (l *ConservingLedger) CommitHold(accountID string, destAccountID string, amount int64, txID string) error {
	if amount <= 0 {
		return ErrInvalidAmount
	}

	l.accountsLock.RLock()
	acc, exists := l.accounts[accountID]
	destAcc, destExists := l.accounts[destAccountID]
	l.accountsLock.RUnlock()

	if !exists {
		return ErrAccountNotFound
	}
	if !destExists {
		destAcc = l.CreateAccount(destAccountID, 0)
	}

	// Lock in consistent order to prevent deadlocks
	if acc.ID < destAcc.ID {
		acc.mu.Lock()
		destAcc.mu.Lock()
	} else if acc.ID > destAcc.ID {
		destAcc.mu.Lock()
		acc.mu.Lock()
	} else {
		acc.mu.Lock()
	}

	defer func() {
		acc.mu.Unlock()
		if acc.ID != destAcc.ID {
			destAcc.mu.Unlock()
		}
	}()

	if acc.ReservedBalance < amount {
		return ErrHoldMismatch
	}

	acc.ReservedBalance -= amount
	acc.Version++
	acc.UpdatedAt = time.Now().UTC()

	destAcc.AvailableBalance += amount
	destAcc.Version++
	destAcc.UpdatedAt = time.Now().UTC()

	// Double-entry record: Debit Escrow, Credit Destination
	l.appendEntry(LedgerEntry{
		TxID:        txID,
		Type:        EntryCommit,
		DebitAcc:    l.EscrowAccountID,
		CreditAcc:   destAccountID,
		Amount:      amount,
		Timestamp:   time.Now().UTC(),
		Description: fmt.Sprintf("Settlement committed to %s", destAccountID),
	})

	return nil
}

// DirectCommit commits funds directly (Reserve + Commit in one atomic step)
func (l *ConservingLedger) DirectCommit(accountID string, destAccountID string, amount int64, txID string) error {
	if amount <= 0 {
		return ErrInvalidAmount
	}

	l.accountsLock.RLock()
	acc, exists := l.accounts[accountID]
	destAcc, destExists := l.accounts[destAccountID]
	l.accountsLock.RUnlock()

	if !exists {
		return ErrAccountNotFound
	}
	if !destExists {
		destAcc = l.CreateAccount(destAccountID, 0)
	}

	if acc.ID < destAcc.ID {
		acc.mu.Lock()
		destAcc.mu.Lock()
	} else if acc.ID > destAcc.ID {
		destAcc.mu.Lock()
		acc.mu.Lock()
	} else {
		acc.mu.Lock()
	}

	defer func() {
		acc.mu.Unlock()
		if acc.ID != destAcc.ID {
			destAcc.mu.Unlock()
		}
	}()

	if acc.AvailableBalance < amount {
		return ErrInsufficientFunds
	}

	acc.AvailableBalance -= amount
	acc.Version++
	acc.UpdatedAt = time.Now().UTC()

	destAcc.AvailableBalance += amount
	destAcc.Version++
	destAcc.UpdatedAt = time.Now().UTC()

	l.appendEntry(LedgerEntry{
		TxID:        txID,
		Type:        EntryCommit,
		DebitAcc:    accountID,
		CreditAcc:   destAccountID,
		Amount:      amount,
		Timestamp:   time.Now().UTC(),
		Description: fmt.Sprintf("Direct authorization committed to %s", destAccountID),
	})

	return nil
}

// ReleaseHold returns reserved funds back to the user's available balance
func (l *ConservingLedger) ReleaseHold(accountID string, amount int64, txID string) error {
	l.accountsLock.RLock()
	acc, exists := l.accounts[accountID]
	l.accountsLock.RUnlock()

	if !exists {
		return ErrAccountNotFound
	}

	acc.mu.Lock()
	defer acc.mu.Unlock()

	if acc.ReservedBalance < amount {
		return ErrHoldMismatch
	}

	acc.ReservedBalance -= amount
	acc.AvailableBalance += amount
	acc.Version++
	acc.UpdatedAt = time.Now().UTC()

	l.appendEntry(LedgerEntry{
		TxID:        txID,
		Type:        EntryRelease,
		DebitAcc:    l.EscrowAccountID,
		CreditAcc:   accountID,
		Amount:      amount,
		Timestamp:   time.Now().UTC(),
		Description: fmt.Sprintf("Hold released for tx %s", txID),
	})

	return nil
}

// RecordDeficit handles post-partition overdraw by crediting merchant and debiting deficit account
func (l *ConservingLedger) RecordDeficit(accountID string, destAccountID string, amount int64, txID string) error {
	l.accountsLock.RLock()
	acc, exists := l.accounts[accountID]
	destAcc, destExists := l.accounts[destAccountID]
	l.accountsLock.RUnlock()

	if !exists {
		acc = l.CreateAccount(accountID, 0)
	}
	if !destExists {
		destAcc = l.CreateAccount(destAccountID, 0)
	}

	acc.mu.Lock()
	destAcc.mu.Lock()
	defer acc.mu.Unlock()
	defer destAcc.mu.Unlock()

	// Post to deficit: account balance becomes negative or liability is booked to clearing
	acc.AvailableBalance -= amount
	acc.Version++
	acc.UpdatedAt = time.Now().UTC()

	destAcc.AvailableBalance += amount
	destAcc.Version++
	destAcc.UpdatedAt = time.Now().UTC()

	l.appendEntry(LedgerEntry{
		TxID:        txID,
		Type:        EntryDeficit,
		DebitAcc:    accountID,
		CreditAcc:   destAccountID,
		Amount:      amount,
		Timestamp:   time.Now().UTC(),
		Description: fmt.Sprintf("Deficit settlement committed for partition tx %s", txID),
	})

	return nil
}

func (l *ConservingLedger) appendEntry(entry LedgerEntry) {
	entry.EntryID = atomic.AddInt64(&l.entryCounter, 1)
	l.entriesLock.Lock()
	l.entries = append(l.entries, entry)
	l.entriesLock.Unlock()
}

// AuditConservation calculates total balances across all accounts and validates double-entry conservation
func (l *ConservingLedger) AuditConservation() (totalAvailable int64, totalReserved int64, totalBalance int64, entryCount int) {
	l.accountsLock.RLock()
	defer l.accountsLock.RUnlock()

	for _, acc := range l.accounts {
		acc.mu.RLock()
		totalAvailable += acc.AvailableBalance
		totalReserved += acc.ReservedBalance
		acc.mu.RUnlock()
	}

	l.entriesLock.RLock()
	entryCount = len(l.entries)
	l.entriesLock.RUnlock()

	totalBalance = totalAvailable + totalReserved
	return totalAvailable, totalReserved, totalBalance, entryCount
}
