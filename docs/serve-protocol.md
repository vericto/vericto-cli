# `vericto serve --stdio`: protocol v1

`vericto serve --stdio` is a long-lived local evaluation server. The Vericto
SDKs use it for their offline mode: they spawn the CLI once and send it SQL
over stdin/stdout. It evaluates with the engine built into the binary and its
standard rules, the same code path as `vericto check --offline`. It never
opens a network connection, needs no account, and reads no config file.

The SDKs are Apache-2.0 and the CLI and engine are AGPL-3.0-only. The SDKs
talk to a separate process and do not link the engine.

Available since CLI 2.1.0 (unreleased), in every build that has the `offline`
feature, which includes every release build. A build without it prints an
error and exits `2`.

## Transport

- JSON Lines: one JSON object per line, UTF-8, terminated by `\n` (a `\r`
  before it is accepted). Blank lines are ignored.
- **stdout** carries protocol lines only: the hello line, then responses.
- **stderr** carries diagnostics only. They never contain SQL. A client may
  discard stderr or log it.
- No network listener of any kind.

## Startup

Before reading any request, the server writes one hello line:

```json
{"type":"hello","protocol":1,"cli_version":"2.1.0","engine_version":"5.0.0","profiles":["runtime","ci"],"max_line_bytes":1048576}
```

| Field | Meaning |
|---|---|
| `type` | Always `"hello"`. |
| `protocol` | `1`. A client must refuse a version it does not know. |
| `cli_version` | The CLI's version. |
| `engine_version` | The embedded `vericto-engine` version. It also appears in each result's `engine_version` and `ruleset_version` (`standard@engine-<version>`). |
| `profiles` | The profiles this server accepts. |
| `max_line_bytes` | The request line limit in force (`--max-line-bytes`). It is an addition to the original v1 sketch. |

Keys may come in any order. Clients must ignore fields they do not know: the
server may add fields within protocol 1.

## Requests

### `check`

```json
{"id":"42","op":"check","sql":"DROP TABLE users;","dialect":"postgres","profile":"runtime"}
```

| Field | Required | Meaning |
|---|---|---|
| `id` | yes | A string chosen by the client, echoed in the response. It is not checked for uniqueness. |
| `op` | yes | `"check"` |
| `sql` | yes | The SQL text, with one or more statements. Must not be empty or whitespace only. |
| `dialect` | no, default `postgres` | `postgres`, `mysql`, `oracle`, `mssql`, `snowflake`, `sqlite`, or the aliases the engine also accepts (`postgresql`, `sqlserver`, `tsql`, `sqlite3`). |
| `profile` | no, default `runtime` | `runtime` or `ci`, see below. |

Unknown fields are ignored. A `null` `dialect` or `profile` counts as absent.

Response:

```json
{"id":"42","ok":true,"result":{"summary":{…},"queries":[…],"exit_code":1,"mode":"offline","engine_version":"5.0.0"}}
```

`result` is exactly the JSON document that `vericto check --offline --format
json` prints for the same SQL (under the `ci` profile), as one compact value.
The document is built by the same function:

- `summary`: `total`, `blocked`, `allowed`, `flagged`, `monitored`,
  `parse_errors` and `ruleset_version`.
- `queries`: one entry per request, with `line` (always `1`), `file_index`
  (`null`), `status` (`ALLOWED`, `FLAGGED`, `MONITORED`, `BLOCKED`,
  `PARSE_ERROR`), `action`, `rule_code`, `severity`, `ast_node_path`,
  `suggested_fix` and `sql_preview` (the first 100 characters of the SQL).
- `exit_code`: `1` when the verdict is BLOCKED, `0` otherwise. It is the
  verdict's code, not a process exit code.
- `mode`: `"offline"`.
- `engine_version`.

**Granularity.** Each request is one input, as a file is for `check
--offline`. Several statements in one `sql` produce one result: the finding
with the strongest action across all of them. In `DROP TABLE a; UPDATE
accounts SET balance = 0;` the result is BLOCKED by `VERICTO-030`, under both
profiles. To get a verdict per statement, send each statement as its own
request.

**Size.** Input over 10 MiB is a `PARSE_ERROR` result, as in `check
--offline`. The default line limit of 1 MiB is lower, so this applies only
with a larger `--max-line-bytes`.

### Profiles

The hosted API has two channels, and they differ in one setting only:

- **`runtime`** (default) matches the Runtime API (`POST
  /api/v1/proxy/query`), MCP `check_sql` and the proxy's local mode. There is
  no schema-migration cap, so `DROP TABLE users` is BLOCKED (`VERICTO-010`,
  action `block`).
- **`ci`** matches `vericto check --offline` and `POST /api/v1/ci/check-key`.
  The DDL rules VERICTO-010..019 (DROP, ALTER, TRUNCATE…) are capped at
  FLAGGED, so `DROP TABLE users` is FLAGGED (action `flag`, `exit_code` 0).

Everything else is the same under both profiles: the 42 standard rules at
their default severities (Critical and High block, Medium flags, Low is
monitored), and parse errors are allowed and reported.

### `ping`

```json
{"id":"7","op":"ping"}
```
→ `{"id":"7","ok":true}`

### `shutdown`

```json
{"op":"shutdown"}
```

The server stops reading and exits `0`. If the request has an `id`, the
server answers `{"id":"…","ok":true}` before it exits. Lines after a
`shutdown` are not read. **EOF on stdin** does the same: the server answers
every complete line it has read, then exits `0`.

## Errors

```json
{"id":"42","ok":false,"error":{"code":"UNSUPPORTED_DIALECT","message":"unsupported dialect 'db2' (use postgres, mysql, oracle, mssql, snowflake or sqlite)"}}
```

| `code` | When |
|---|---|
| `INVALID_REQUEST` | The line is not valid UTF-8, is not JSON, or is not an object. `id` is not a string. `op` is missing or unknown. `check`/`ping` has no `id`. `sql` is missing, not a string, or empty. `dialect` or `profile` is not a string. `profile` is unknown. |
| `UNSUPPORTED_DIALECT` | `dialect` is a string the engine does not know. |
| `TOO_LARGE` | The line is longer than `max_line_bytes`, not counting its `\n`. The line is read to its end and discarded. |
| `INTERNAL` | The engine failed on this request. The failure is logged on stderr, without the SQL. |

`id` is `null` when the line had no usable id. That covers malformed JSON,
an oversized line, and an `id` that is not a string. **After every error the
server keeps running** and reads the next line. `message` is for humans; do
not parse it.

## Ordering, pipelining and memory

- Clients may pipeline: write many requests without waiting for answers.
- Protocol v1 servers evaluate one request at a time and **answer in request
  order**, one response per request line. The exceptions are blank lines and a
  `shutdown` without an id, which get no response. Match responses by `id`
  anyway. A future protocol version that answers out of order would bump
  `protocol`.
- Memory is bounded. The server holds one request line, at most
  `max_line_bytes`, and has no queue. A client that writes faster than the
  server answers is slowed down by the pipe. A client that pipelines must read
  stdout concurrently with writing to stdin, for example on another thread or
  with async I/O. Otherwise both pipes can fill up and block each other.
- For throughput, run one server per worker. The server is single-threaded.

## Limits and flags

| Flag | Default | Meaning |
|---|---|---|
| `--stdio` | required | The transport. It is the only one; `serve` without it exits `2`. |
| `--max-line-bytes <BYTES>` | `1048576` (1 MiB) | Largest request line, from 1024 bytes to 64 MiB. A value outside that range exits `2` before the hello line. |

## Exit codes

| Code | When |
|---|---|
| `0` | EOF on stdin, a `shutdown`, or the client closed stdout. |
| `2` | Usage error (no `--stdio`, a bad flag), a build without the `offline` feature, or an I/O error on stdin or stdout. |

## Security and privacy

- stdio only. The process opens no socket and contacts no host, Vericto
  included.
- Verdicts depend on the request and the embedded engine only. The server
  reads no environment variable, no `~/.config/vericto` and no
  `.vericto.toml`.
- SQL never reaches stderr. Its only way out is the response's `sql_preview`
  (the first 100 characters), and the response goes to the client that sent
  the SQL.
- What offline mode cannot do, by construction: custom rules, severity
  overrides, sensitive columns and masking, agent allowlists, audit records and
  signed receipts. Those exist only in a workspace, online.

## Example session

```text
$ vericto serve --stdio
{"cli_version":"2.1.0","engine_version":"5.0.0","max_line_bytes":1048576,"profiles":["runtime","ci"],"protocol":1,"type":"hello"}
{"id":"1","op":"check","sql":"DROP TABLE users"}
{"id":"1","ok":true,"result":{"engine_version":"5.0.0","exit_code":1,"mode":"offline","queries":[{"action":"block","ast_node_path":"DropStmt","file_index":null,"line":1,"rule_code":"VERICTO-010","severity":"critical","sql_preview":"DROP TABLE users","status":"BLOCKED","suggested_fix":"Use a versioned migration tool (Flyway, Prisma Migrate, Alembic, Rails migrations)"}],"summary":{"allowed":0,"blocked":1,"flagged":0,"monitored":0,"parse_errors":0,"ruleset_version":"standard@engine-5.0.0","total":1}}}
{"id":"2","op":"ping"}
{"id":"2","ok":true}
{"op":"shutdown"}
```
