# Shared client fixtures

Documents that every client must agree on, kept here rather than in
`sealbook-test-data` so they are versioned with the code that has to satisfy
them: a change to a wire type or a payload schema and the fixture it breaks
move in one commit.

`sealbook-test-data` keeps third-party input (Thunderbird CSV exports, an ICS
file, an image). This directory keeps sealbook's own output.

## Who reads them

| reader | how |
| --- | --- |
| Rust | `concat!(env!("CARGO_MANIFEST_DIR"), "/../sealbook-protocol/fixtures/...")` |
| TypeScript | `readFixture("...")` from `sealbook-web/src/test/fixtures.ts` |
| Kotlin | `SharedFixtures.read("...")` from `sealbook-app`'s test sources |

The TypeScript and Kotlin readers resolve a sibling `sealbook` checkout, which
both builds already require for the wasm module and the JNI library.

## Contents

- `v1.0.0-account-export.json` — the v1.0.0 release's own account export,
  carrying a content type that release had no parser for and a payload that is
  not JSON. Pins that both the CLI and the web importer still round-trip every
  object a released client could have written.
- `payloads/calendar-event.json`, `payloads/calendar.json`,
  `payloads/calendar-archived.json` — the literal output of sealbook-web's
  `putCalendarEvent` and `putCalendar`. Android's `CalendarWireParityTest` read
  these as copied literals until they moved here; now the web's
  `wireParity.test.ts` and this crate's `tests/fixtures.rs` are held to the
  same bytes. Pins the keys and values of the calendar plaintext, which no
  server check covers.

- `rosters/chain-with-revoke.json` — three roster steps under one collection
  key: alpha alone, alpha and beta, then alpha again with beta revoked. Carries
  the collection key and the device ids, so a reader can verify the chain rather
  than only parse it. Pins the one case no other fixture covers, a device that
  was in the account and is no longer, and it is what `sealbook-core`'s roster
  tests, `sealbook-web/src/lib/rosterParity.test.ts` and Android's
  `RosterChainTest` are all held to.

  Generated from fixed seeds by the ignored
  `regenerate_the_roster_chain_fixture` test in
  `crates/sealbook-core/tests/roster.rs`:

  ```
  REGENERATE_ROSTER_FIXTURE=1 cargo test -p sealbook-core -- --ignored regenerate
  ```

  `the_checked_in_fixture_is_what_the_generator_builds` compares transcripts
  rather than bytes, because ML-DSA signing need not be deterministic.

- `manifests/one-write.json` — a five-object collection in four buckets, with
  its signed manifest served both ways (whole, and as the two buckets one write
  touches) and the root that write produces. Signed by the same alpha device as
  the roster fixture, under the same collection, so the two describe one
  account. Pins that the bucketed check and the whole-collection check reach the
  same root, which is the property the bucket read rests on, and it is what
  `sealbook-core`'s manifest tests,
  `sealbook-web/src/lib/manifestParity.test.ts` and Android's
  `ManifestChainTest` are all held to.

  Generated from fixed seeds by the ignored `regenerate_the_manifest_fixture`
  test in `crates/sealbook-core/tests/manifest.rs`:

  ```
  REGENERATE_MANIFEST_FIXTURE=1 cargo test -p sealbook-core -- --ignored regenerate
  ```

  As with the roster fixture, the check compares the digests and the root rather
  than the bytes.

- `changes/paged-walk.json` — one collection served as two pages of the change
  feed, with the request path each page answers, and the signed manifest both
  pages carry. Holds every row kind a read has to tell apart: a superseded
  revision still in the log, a row-level tombstone, a sealed tombstone, and a
  row sealed under a key epoch the reader has not caught up to. Signed by the
  same alpha device as the roster and manifest fixtures and under the same
  collection, so all three describe one account. Pins the object set, the
  tombstones and the unreadable list a read produces, which is phase 3's whole
  claim, and it is what `sealbook-core`'s sync tests,
  `sealbook-web/src/lib/syncParity.test.ts` and Android's `VaultWalkTest` are
  all held to.

  Generated from fixed seeds by the ignored `regenerate_the_sync_fixture` test
  in `crates/sealbook-core/tests/sync.rs`:

  ```
  REGENERATE_SYNC_FIXTURE=1 cargo test -p sealbook-core -- --ignored regenerate
  ```

  The check compares the verdicts and the request paths rather than the bytes,
  because the AEAD nonce is random and ML-DSA signing need not be
  deterministic.

One payload per remaining content type is phase 8 work in `UNIFICATION_PLAN.md`,
added as each type moves into `sealbook-core`.

## Adding one

A fixture is only worth keeping if more than one implementation reads it, or if
it is output from a release that can no longer be regenerated. Name it for what
it pins, note it in the table above, and say in the comment which drift it
catches.
