# Import samples

`contacts.vcf`, `contacts.csv` and `calendar.ics` are read by `sealbook-core`
(`vcard_parse`, `csv_parse`, `ics_parse`) and by every client's tests.
`expected.json` holds what each must become:

- `vcf`, `csv`: the stored card for each contact, with `created` and `updated` left out.
- `ics_parsed`: core's reading of the calendar, before a host resolves any zone.
- `ics`: the stored events once a host has resolved the zones, in `Europe/London`.

Regenerate the core-owned parts with
`REGENERATE_IMPORT_FIXTURE=1 cargo test -p sealbook-core --test imports -- --ignored regenerate`.

An imported instant is written in whole seconds with a `Z` (`2026-10-01T09:00:00Z`),
never with milliseconds. Core reads either form; only imports are held to this.
