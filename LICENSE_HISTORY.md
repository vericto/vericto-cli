# License history

This file identifies the license boundary of published `vericto-cli` source.
It is part of the release record. A Git author or committer date alone is not
proof of when source was first made available.

## Current license

| Source | License |
|---|---|
| Tag `v2.0.0` and later releases, beginning with the transition represented by this working tree | GNU Affero General Public License, version 3 only (`AGPL-3.0-only`), or a separate commercial license from Vericto S.A.S. |
| Tags `v1.10.0` through `v1.13.3` | Functional Source License, Version 1.1, ALv2 Future License (`FSL-1.1-ALv2`) |
| Version 1.9.1 and earlier releases | Elastic License 2.0 (`Elastic-2.0`) |

The last FSL release is:

- tag: `v1.13.3`;
- commit: `ff8f1b8cbfb28ee2b6ed8015c29e7518b8fb9058`;
- first documented public availability: 2026-11-01 (UTC), through pull request 69.

The first FSL commit is `530a641b82a9bde22861dcf75c8f057c27fb7c65`
(`release 1.10.0: license the CLI under FSL-1.1-ALv2`). Every commit from that
one up to the commit that introduced the AGPL is under the FSL, including
commits on `main` after `v1.13.3` that carry no tag.

The first AGPL release will be identified by tag `v2.0.0`. The tag itself is
the immutable mapping to its commit SHA. Create and publish that tag at the
same time as the release. Do not publish an artifact numbered `1.13.3` or any
earlier version from the AGPL working tree.

## FSL future-license schedule

FSL 1.1 grants Apache License 2.0 for each version on the second anniversary of
the date Vericto first made that version available. The dates below use the
creation date of the public pull request that introduced each version number
as the earliest retained evidence. If Vericto finds earlier public evidence for
a specific commit or artifact, that earlier date controls for that version.

For `v1.10.0`, `v1.12.1` and `v1.13.0` the tag points at a later commit than
the one that introduced the version number, because a merge landed in between.
The date comes from the pull request that introduced the version number.

| Release | Tag commit | Pull request | Documented public date (UTC) | Apache 2.0 no later than |
|---|---|---:|---:|---:|
| `v1.10.0` | `300b7fc1d2a63ff804ebb4b16713e5e8a2303b6e` | 55 | 2026-10-19 | 2028-10-19 |
| `v1.10.1` | `a028e75b15b8d04920ffabfbebccf92ef48663d2` | 57 | 2026-10-19 | 2028-10-19 |
| `v1.11.0` | `9407d2cc115b8bafd99e86907842eedae29808d0` | 58 | 2026-10-20 | 2028-10-20 |
| `v1.12.0` | `3b0d4f65985d34b2e4909d7fece7efa06b661993` | 59 | 2026-10-23 | 2028-10-23 |
| `v1.12.1` | `6c3fbfea2d5e2216ae8b11a807301075d7c663e5` | 62 | 2026-10-26 | 2028-10-26 |
| `v1.13.0` | `23fcfddb6c55fd191d06c38bd8c99fcc944a3c0b` | 65 | 2026-10-31 | 2028-10-31 |
| `v1.13.1` | `0d47f94906dcb610ffcbc06e3926c0a67140a5b9` | 66 | 2026-11-01 | 2028-11-01 |
| `v1.13.2` | `efa6c48a173124687fa104ff49d05a860cb1bd71` | 68 | 2026-11-01 | 2028-11-01 |
| `v1.13.3` | `ff8f1b8cbfb28ee2b6ed8015c29e7518b8fb9058` | 69 | 2026-11-01 | 2028-11-01 |

The table lists tagged releases. Another intermediate FSL commit or package
may have its own date because FSL defines the Software as each version made
available with its terms. Preserve pull-request, package and release records.
Do not infer the effective date only with `git rev-list --before`.

## Elastic License 2.0

Version 1.9.1 and earlier are under the Elastic License 2.0. The last tag
under it is `v1.9.0`. Version 1.9.1 (commit
`ccb23d23408c79fe002d423e7d80fa58ea16bcba`, pull request 54) was never tagged
and remains under it.

The controlling text remains the `LICENSE` file distributed with each version:

```sh
git show v1.13.3:LICENSE
git show v1.9.0:LICENSE
```
