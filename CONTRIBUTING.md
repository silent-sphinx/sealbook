# Contributing

Pull requests are welcome on the Sealbook server, protocol and command line client.

## Sign your commits

Every commit needs a `Signed-off-by` line. It certifies the Developer
Certificate of Origin reproduced below: that you wrote the change, or otherwise
hold the right to contribute it under this project's licence.

Git writes the line for you with `-s`, taking it from your `user.name` and
`user.email`, so both need to be set and real:

```bash
git commit -s -m "fix: ..."
```

Forgot one? Amend the last commit:

```bash
git commit --amend -s --no-edit
```

Or sign off a whole branch at once:

```bash
git rebase --signoff main
```

A pull request whose commits are not all signed off fails the DCO check and
cannot be merged.

## What signing off does not do

It leaves the copyright with you. This is not a copyright assignment and not a
contributor licence agreement: your contribution is simply licensed to the
project under the Apache License, Version 2.0, on the same terms as the rest of
it.

## Before you open a pull request

Run what CI runs, so review is about the change rather than the build:

```bash
cargo fmt --check
cargo clippy --all-targets
cargo test
```

## Developer Certificate of Origin

```
Developer Certificate of Origin
Version 1.1

Copyright (C) 2004, 2006 The Linux Foundation and its contributors.

Everyone is permitted to copy and distribute verbatim copies of this
license document, but changing it is not allowed.


Developer's Certificate of Origin 1.1

By making a contribution to this project, I certify that:

(a) The contribution was created in whole or in part by me and I
    have the right to submit it under the open source license
    indicated in the file; or

(b) The contribution is based upon previous work that, to the best
    of my knowledge, is covered under an appropriate open source
    license and I have the right under that license to submit that
    work with modifications, whether created in whole or in part
    by me, under the same open source license (unless I am
    permitted to submit under a different license), as indicated
    in the file; or

(c) The contribution was provided directly to me by some other
    person who certified (a), (b) or (c) and I have not modified
    it.

(d) I understand and agree that this project and the contribution
    are public and that a record of the contribution (including all
    personal information I submit with it, including my sign-off) is
    maintained indefinitely and may be redistributed consistent with
    this project or the open source license(s) involved.
```
