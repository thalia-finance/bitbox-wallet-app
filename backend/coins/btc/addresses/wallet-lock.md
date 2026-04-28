# Upstream PR: narrow `AddressChain.EnsureAddresses` writer-lock scope

Plan for an upstream `bitbox-wallet-app` PR that fixes a latent
deadlock pattern introduced by the recent "address behind interface"
refactor (commit `fbdeab364`). The bug is invisible against the
upstream's bbolt `DBInterface` impl but trips on any embedder whose
`Begin` is a contended Go-level operation (e.g. our SQLite-backed
impl with `BEGIN IMMEDIATE` semantics).

## Problem

In `backend/coins/btc/addresses/addresschain.go::EnsureAddresses`,
the writer lock is held across the call into `unusedTailCount` →
`isAddressUsed`, which is an embedder-supplied callback that
typically opens a DB transaction. That creates an unbounded
critical section (the writer lock is held for the entire DB I/O)
and locks out any concurrent `LookupByAddressID` / `GetUnused` call
for that whole duration.

It's also the precondition for an AB-BA deadlock when the
embedder's `DBInterface` impl holds any Go-level lock at `Begin`
time:

- **Path A** (`subscribeAddress` callback → `Account.onAddressStatus`
  → `ensureAddresses` → `AddressChain.EnsureAddresses`): holds
  `addressesLock.Lock()` and waits on the embedder's DB.
- **Path B** (`Transactions.Transactions(account.IsChange)`): opens
  a DB read tx and, inside the callback, calls `IsChange` →
  `Account.lookupAddressByID` → `AddressChain.LookupByAddressID` →
  wants `addressesLock.RLock()`.

If the embedder's `Begin` takes any lock that's held by Path B's
open DB tx, the cycle closes.

## Why bbolt hides it

bbolt's `Begin(false)` returns immediately with a snapshot — readers
don't block on writers (MVCC) and don't acquire a Go-level lock that
another goroutine could be holding. So Path A's wait inside
`unusedTailCount`'s DB call is bounded by bbolt's own internal queue
and never crosses the `addressesLock` boundary. The bug is latent
in upstream but only surfaces against `DBInterface` impls where
`Begin` is itself a contended Go-level operation.

(Real-world repro: a SQLite-backed `DBInterface` with `BEGIN
IMMEDIATE` semantics — every tx takes the writer lock, so the cycle
becomes an actual deadlock. This is what we hit in thalia.)

## The fix

Drop the writer lock around the `unusedTailCount` call; re-acquire
only to mutate. The chain only grows, so an outdated
`unusedAddressCount` results in adding strictly more addresses than
required — never fewer — which is safe (and converges on the next
caller's iteration).

```go
func (addresses *AddressChain) EnsureAddresses() ([]AccountAddress, error) {
	var unusedAddressCount int
	var err error
	func() {
		defer addresses.addressesLock.RLock()()
		unusedAddressCount, err = addresses.unusedTailCount()
	}()
	if err != nil {
		return nil, err
	}

	defer addresses.addressesLock.Lock()()
	addedAddresses := []AccountAddress{}
	for i := 0; i < addresses.gapLimit-unusedAddressCount; i++ {
		addedAddresses = append(addedAddresses, addresses.addAddress())
	}
	return addedAddresses, nil
}
```

That's it — one function, behaviour-preserving for bbolt, fixes the
deadlock for non-bbolt embedders.

## Unit test (no DB needed)

The test demonstrates the *symptom* — that `LookupByAddressID` is
locked out while `EnsureAddresses` is mid-`isAddressUsed` callback —
using a controllable fake `isAddressUsed`. No bbolt needed.

Sketch (in `backend/coins/btc/addresses/addresschain_test.go`):

```go
func TestEnsureAddresses_DoesNotBlockLookupDuringIsAddressUsed(t *testing.T) {
	inCallback := make(chan struct{})
	release    := make(chan struct{})

	isAddressUsed := func(addr AccountAddress) (bool, error) {
		// Signal that we're inside isAddressUsed, then block until
		// the test releases us. With the bug, EnsureAddresses holds
		// the writer lock across this entire window.
		close(inCallback)
		<-release
		return false, nil
	}

	chain := NewAddressChain(/* … */, isAddressUsed /*, etc */)
	// Pre-populate with at least one address so unusedTailCount has
	// something to call isAddressUsed against. (Use the same helper
	// the existing tests use.)

	ensureDone := make(chan struct{})
	go func() {
		_, _ = chain.EnsureAddresses()
		close(ensureDone)
	}()

	<-inCallback // EnsureAddresses is now mid-isAddressUsed.

	// With the bug: EnsureAddresses still holds addressesLock.Lock(),
	// so LookupByAddressID's RLock blocks forever.
	// With the fix: EnsureAddresses has released the writer lock,
	// so LookupByAddressID returns promptly.
	lookupDone := make(chan struct{})
	go func() {
		_ = chain.LookupByAddressID("any-id")
		close(lookupDone)
	}()

	select {
	case <-lookupDone:
		// Pass.
	case <-time.After(2 * time.Second):
		t.Fatal("LookupByAddressID blocked while EnsureAddresses " +
			"was in isAddressUsed — writer lock held across callback")
	}

	close(release)
	<-ensureDone
}
```

Without the patch: this test deadlocks for 2s and fails.
With the patch: the lookup returns promptly and the test passes.

(You may need to look at `backend/coins/btc/addresses/test/test.go`
for the existing `NewAddressChain` setup helpers — copy the pattern
from one of the existing `addresschain_test.go` tests.)

## PR framing

Lead with **"narrow the writer-lock scope in `EnsureAddresses`"**
and the test demonstrating that `LookupByAddressID` shouldn't block
during `isAddressUsed`. Mention the AB-BA deadlock under non-bbolt
`DBInterface` impls as motivation in the description, but don't
make the PR title about "SQLite" — the fix is generally beneficial
(shorter critical sections, lower contention on `addressesLock`)
even for the upstream's bbolt-only callers.

## Files involved

- **Patch**: `backend/coins/btc/addresses/addresschain.go` —
  modify `EnsureAddresses`.
- **Test**: `backend/coins/btc/addresses/addresschain_test.go` —
  add the test above.
- **Reference**: existing `EnsureAddresses` is around line 105; the
  existing test setup helpers and `NewAddressChain` invocations are
  in the same package.

## Local context

In the thalia repo, the same patch already lives in our
`code-ingest/bitbox-wallet-app` copy with an explanatory comment.
Once the upstream PR merges (or we cut a release in our
`thalia-finance/bitbox-wallet-app` fork), revert the
`replace … => ../../code-ingest/bitbox-wallet-app` in
`native/go/go.mod` back to a versioned dependency.
