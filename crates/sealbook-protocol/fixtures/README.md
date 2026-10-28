# Shared client fixtures

Documents that every client must agree on.

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
  `payloads/calendar-archived.json` — the literal output of the writers that
  predate `sealbook-core`, which was sealbook-web's `putCalendarEvent` and
  `putCalendar`. Superseded as the calendar document by `payloads/calendars.json`
  below, and kept because they are the one record of what a released client
  wrote: each must still read and write back unchanged through core, which
  `calendarParity.test.ts`, Android's `CalendarWireParityTest` and this crate's
  `tests/fixtures.rs` are what assert.

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

- `rotation/plan.json` — one collection as a verified read leaves it, with the
  plan a rotation makes for it: which rows are re-sealed and at which revision,
  which tombstone the manifest carries, which row is retired, and the sequence
  and epoch the rotation advances to. Alongside it the row a rotation refuses on
  and the six rosters that decide who keeps a wrap of the new key. Under the
  same collection and alpha device as the fixtures above. Pins the one rule no
  server check covers: a rotation refuses on a row it cannot re-seal where every
  other read counts it and carries on, which is the area of the 2026-10-20
  tombstone bug. Read by `sealbook-core`'s rotation tests,
  `sealbook-web/src/lib/rotationParity.test.ts` and Android's
  `VaultRotationTest`.

  Generated from fixed seeds by the ignored `regenerate_the_rotation_fixture`
  test in `crates/sealbook-core/tests/rotation.rs`:

  ```
  REGENERATE_ROTATION_FIXTURE=1 cargo test -p sealbook-core -- --ignored regenerate
  ```

  The check compares the plan and the verdicts rather than the bytes, because
  the AEAD nonce is random, which also means a carried tombstone's digest is of
  the bytes that run stored.

- `pairing/handshake.json` — one account mid-pairing, as both sides see it: the
  join response the new device checks, the status response the approver
  previews, the code both sides have to compute from those, and the roster the
  approval extends. Alongside them every refusal either side can raise, the
  forms of the code a user may type, and the lookup paths a typed code resolves
  to. Under the same collection and alpha device as the fixtures above, with the
  joining device as delta. Pins the rule the server cannot check for either
  side: each computes the confirmation code itself and only ever compares the
  server's copy against it, because a server that substituted the joining
  device's keys could show the real code and keep the ones it swapped in. Read
  by `sealbook-core`'s pairing tests,
  `sealbook-web/src/lib/pairingParity.test.ts` and Android's
  `DevicePairingTest`.

  Generated from fixed seeds by the ignored `regenerate_the_pairing_fixture`
  test in `crates/sealbook-core/tests/pairing.rs`:

  ```
  REGENERATE_PAIRING_FIXTURE=1 cargo test -p sealbook-core -- --ignored regenerate
  ```

  The check compares the codes, the refusals and the served responses rather
  than an approval's bytes, because the HPKE wrap in one is freshly random.

- `auth/account.json` is one signed-in account, and every decision the four
  auth flows make that is not fresh randomness: the usernames and phrases a user
  actually types and what each one is sent or derived as, the path each round
  posts to, the login responses and which key wrap each has core open, the
  recovery start response as the server serves it, and every refusal any flow
  can raise. Under the same collection and alpha device as the fixtures above.
  Pins the decisions the three clients had each been making for themselves: that
  a username is trimmed before it is sent, that a phrase is lowercased before it
  is parsed, that the collection the server echoes has to be the one the genesis
  roster was signed over, and that a login with no wrap for this device is a
  revoked device rather than a crypto error. Read by `sealbook-core`'s auth
  tests, `sealbook-web/src/lib/authParity.test.ts` and Android's
  `AccountAuthTest`.

  Generated from fixed seeds by the ignored `regenerate_the_auth_fixture` test
  in `crates/sealbook-core/tests/auth.rs`:

  ```
  REGENERATE_AUTH_FIXTURE=1 cargo test -p sealbook-core -- --ignored regenerate
  ```

  The check compares the usernames, phrases, paths, wrap choices and refusals
  rather than the request bodies, because almost every body here is an OPAQUE
  message, an HPKE wrap or a signature over one, and so differs on every run.
  The recovery start response is the generator's output once for the same
  reason: the phrase wrap in it carries a fresh nonce.

- `attachments/attachments.json`

  Pins how an attachment's size becomes a chunk count, the paths of the four
  rounds, the nonce header, the per-chunk digests and the content hash rolled
  from them, the sweep's grace period, and what each refusal is called. Read by
  `sealbook-core`'s attachment tests,
  `sealbook-web/src/lib/attachmentParity.test.ts` and Android's
  `AttachmentTest`.

  Generated by the ignored `regenerate` test in
  `crates/sealbook-core/tests/attachments.rs`:

  ```
  REGENERATE_ATTACHMENT_FIXTURE=1 cargo test -p sealbook-core --test attachments -- --ignored regenerate
  ```

  `sealed_chunk` is the generator's output once, because `encrypt_chunk` draws a
  fresh nonce and so cannot be re-derived. Every language opens that one chunk,
  which is what proves the three agree on the chunk AAD rather than only on the
  key: the same chunk is also tried one position along, under one more chunk,
  and under another attachment and collection, and all four must fail.

- `payloads/notes.json` is the note and notebook plaintext itself, byte for
  byte: a draft and the one spelling it writes, a stored payload and the record
  it reads back as, for the cases the three clients disagreed about. Whether a
  title is trimmed, what an untitled and an unparsable note are listed as, which
  name an unnamed notebook takes, whether an edit keeps a field the editing host
  cannot show, and what happens to a payload from a newer schema major. Read by
  `sealbook-core`'s note tests, `sealbook-web/src/lib/noteParity.test.ts` and
  Android's `NotePayloadTest`.

  Generated by the ignored `regenerate` test in
  `crates/sealbook-core/tests/notes.rs`:

  ```
  REGENERATE_NOTE_FIXTURE=1 cargo test -p sealbook-core --test notes -- --ignored regenerate
  ```

  Unlike every fixture above it this one pins bytes rather than verdicts, and it
  can because core writes the payload for all three hosts: `serde_json::Map` is
  ordered, so one payload has one spelling. That is also why it is the only
  fixture with no randomness in it — there is no key, nonce or signature at this
  layer, just the clock, which core takes from its caller and the fixture fixes.

- `payloads/calendars.json` is the calendar and event plaintext itself, byte
  for byte, as `payloads/notes.json` is for notes: a draft and the one spelling
  it writes, a stored payload and the record it reads back as, for the cases the
  three clients disagreed about. Whether a field is trimmed, whether an absent
  one is omitted or written null, which name an unnamed calendar takes, whether a
  rename keeps the colour and the flags, what becomes of a repeat rule this build
  cannot name, and what happens to a payload from a newer schema major. Read by
  `sealbook-core`'s calendar tests,
  `sealbook-web/src/lib/calendarParity.test.ts` and Android's
  `CalendarPayloadTest`.

  Generated by the ignored `regenerate` test in
  `crates/sealbook-core/tests/calendars.rs`:

  ```
  REGENERATE_CALENDAR_FIXTURE=1 cargo test -p sealbook-core --test calendars -- --ignored regenerate
  ```

  It needs no `now`, unlike the note fixture: nothing in a calendar payload comes
  from a clock.

One payload per remaining content type is phase 8 work in `UNIFICATION_PLAN.md`,
added as each type moves into `sealbook-core`.

## Adding one

A fixture is only worth keeping if more than one implementation reads it, or if
it is output from a release that can no longer be regenerated. Name it for what
it pins, note it in the table above, and say in the comment which drift it
catches.

- `imports/contacts.vcf`, `imports/contacts.csv`, `imports/calendar.ics` and
  `imports/expected.json` — sample files for the web and Android importers, and
  the stored payloads both must produce from them. Written by hand, not
  generated; `expected.json` is the contact and event payloads (timestamps
  without `created`/`updated`, instants without milliseconds) after each
  client's own parser and core's writer. Held by `importParity.test.ts` and
  Android's `ImportParityTest`.

