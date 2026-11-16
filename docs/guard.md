# `vericto guard`: database guardrails for coding agents

`vericto guard` checks the shell commands and MCP tool calls that a coding agent
(Claude Code, Cursor, OpenAI Codex) is about to run. It denies the destructive
database operations before they run, and the agent gets the reason, the rule code
and a fix so it can correct itself. It works offline with the engine embedded in
the CLI: no account, no network, and nothing leaves the machine.

What it reads:

- **SQL sent to database clients**: `psql`, `mysql`/`mariadb`, `sqlite3`,
  `sqlcmd`, `duckdb`, `clickhouse-client`, `cockroach sql`, `wrangler d1
  execute`, `turso db shell`, `heroku pg:psql`, `prisma db execute`,
  `manage.py dbshell` and `rails dbconsole`. It reads `-c`/`-e`/`-Q`/`--query`,
  `-f file`, heredocs, here-strings, pipes from `echo`/`printf`/`cat`, and
  `< file`. The SQL is parsed by the same engine as `vericto check --offline`,
  so `SELECT 'DROP TABLE x'`, comments and `grep DROP` are not findings.
- **SQL in MCP tool calls**: any argument named `sql`, `sql_query`,
  `sqlStatements`… and, on database servers, `query`/`statement`. This covers
  Supabase, Neon, Postgres MCP Pro, DBHub, MySQL and SQLite servers, and MCP
  tools that drop or delete by name (`drop-database`, `delete_project`,
  `flushdb`…).
- **Destructive ORM, migration and database commands**: Prisma, Drizzle, Rails,
  Alembic / Flask-Migrate, Django, Laravel, Knex, Sequelize, TypeORM, MikroORM,
  Ecto, Flyway, Liquibase, Doctrine, EF Core, sqlx, Diesel, dbmate, goose,
  golang-migrate, Atlas, Sqitch, Supabase CLI, SQLAlchemy `drop_all`, plus
  `dropdb`, `mysqladmin drop`, `redis-cli FLUSHALL`, `mongosh` drops,
  `pg_restore --clean` and `mongorestore --drop`.
- **Platform commands that delete a database or its data**: `heroku pg:reset`,
  `neonctl projects delete`, `aws rds delete-db-instance`, `gcloud sql instances
  delete`, `docker compose down -v`…
- **Production context**: whether the target looks like production. It reads
  this from the command (`-h db.prod…`, `--env production`, a URL), its
  environment (`RAILS_ENV=production`, `dotenv -e .env.production`), the
  agent's environment, and the project's `.env` / `.env.local` `DATABASE_URL`.
  On production anything that can lose data is denied in every mode.

Commands are read as the shell runs them. That means quoting, `&&` / `;` / `|`,
subshells, `$(…)`, `bash -c '…'`, `eval`, env prefixes, and the launchers in
front of a command: `sudo`, `env`, `timeout`, `npx`, `pnpm`/`yarn`/`bun`
(`exec`, `dlx`, bins), `npm run <script>` (read from `package.json`), `dotenv`,
`dotenvx`, `env-cmd`, `cross-env`, `doppler`/`infisical`/`op run`, `uv`/`poetry`/
`pipenv run`, `bundle exec`, `python -m`, `php artisan`, `docker exec`,
`docker compose exec|run`, `kubectl exec --`, `ssh host '…'`, `heroku run` and
`fly ssh console -C`.

## Install

The guard is part of the `vericto` CLI (2.4.0 or later). Install the CLI first:

```sh
npm install -g @vericto/vericto-cli     # or: brew install vericto/tap/vericto | scoop install vericto/vericto
```

Then pick your agent.

**Claude Code: plugin (recommended)**. Run these inside Claude Code:

```
/plugin marketplace add vericto/vericto-cli
/plugin install vericto-guard@vericto
```

On Claude Code 2.1.275 or later, one line does both:
`/plugin install vericto-guard --marketplace vericto/vericto-cli`.

The plugin's `PreToolUse` hook (matcher `Bash|mcp__.*`) runs
`vericto guard hook --agent claude`. If the CLI is missing, or older than 2.4.0,
the hook lets the call through and shows a warning on every checked call. It does
not block, so installing the plugin before the CLI does not stop Claude from
working. To block until the CLI is installed, set `VERICTO_GUARD_REQUIRE_CLI=1`.

**Claude Code without the plugin, Cursor, Codex**. Run one command in a terminal:

```sh
vericto guard install --agent claude    # ~/.claude/settings.json
vericto guard install --agent cursor    # ~/.cursor/hooks.json
vericto guard install --agent codex     # ~/.codex/hooks.json, then trust it with /hooks in Codex
vericto guard install                   # every agent found on this machine
```

`--scope project` writes the repository's `.claude/settings.json`,
`.cursor/hooks.json` or `.codex/hooks.json` instead; commit it to share it with
the team. `--dry-run` prints the diff and writes nothing. `--bin PATH` sets the
binary the hook runs. By default that is this binary, by its PATH name when it is
on PATH (for example `/opt/homebrew/bin/vericto`, which survives upgrades).

Install merges into the existing file:

- other hooks and settings, and key order, are kept;
- before a file changes, a copy is saved as `<file>.vericto-backup-<unix time>`;
- a file that is not valid JSON is left alone, with an error;
- a second run changes nothing.

`vericto guard uninstall` removes only the guard's entry. `vericto guard status`
shows where it is installed, whether the binary it runs exists, which policy
applies and where the log is.

Codex runs a new or changed hook only after you review and trust it with `/hooks`
([Codex hooks](https://learn.chatgpt.com/docs/hooks.md)).

## Try it

```sh
$ vericto guard test "npx prisma migrate reset --force"
DENY  npx prisma migrate reset --force
  deny  VG-101 [critical] prisma migrate reset drops the database and re-applies every migration
        fix: Run it only against a disposable local database (check DATABASE_URL first), or ask the user to run it.

$ vericto guard test "psql -c 'DELETE FROM users'" --agent codex
DENY  psql -c 'DELETE FROM users'
  deny  VERICTO-001 [critical] DELETE without WHERE in SQL sent by psql (-c): DELETE FROM users
        fix: e.g. `DELETE FROM users WHERE id = $1`
codex hook answer (exit 2):
stderr: vericto guard blocked this command: …

$ vericto guard test --mcp supabase/execute_sql '{"query": "DROP TABLE orders"}'
DENY  mcp:supabase/execute_sql {"query":"DROP TABLE orders"}
  deny  VERICTO-010 [critical] DROP TABLE / DATABASE in SQL sent to MCP tool execute_sql: DROP TABLE orders
```

`test` exits `0` for allow and warn, and `1` for ask and deny. `--format json`
prints the decision as JSON. `--agent claude|cursor|codex` also prints the exact
answer that agent would get.

## How it decides

Each finding has a severity:

| Severity | What | Default verdict |
|---|---|---|
| critical | Loses data by design: DROP TABLE / DATABASE / SCHEMA, TRUNCATE, DELETE / UPDATE without an effective WHERE, COPY … PROGRAM, ORM resets, `dropdb`, FLUSHALL, deleting a database instance | **deny** |
| medium | Can lose data: reverting migrations, engine High rules (DROP COLUMN, RENAME, ALTER TYPE, GRANT…), `docker compose down -v`, deleting a branch | **ask** |
| sensitive | Fine on a development database: applying migrations (`prisma migrate deploy`, `rails db:migrate`…), SQL the guard cannot read (`pg_dump … \| psql`) | allow; **ask** on production |

Then the target and the policy apply:

1. **Production** (some target looks like production): critical and medium are
   denied in every mode. Sensitive is asked.
2. **`allow_local = true`** and every target is known to be local: deny and ask
   become warn. An unknown target is not local.
3. **Mode**: `block` (default) keeps the verdicts; `ask` turns deny into ask;
   `warn` turns deny and ask into warn. Step 1 still applies.
4. **`[[guard.allow]]`** entries allow a finding. They never apply to a
   production target unless the entry says `prod = true`.

The verdict for a command is its strongest finding.

### What each agent gets

| Verdict | Claude Code (`PreToolUse`) | Cursor (`beforeShellExecution` / `beforeMCPExecution`) | Codex (`PreToolUse`) |
|---|---|---|---|
| allow | no output, exit 0. Claude's own permission rules still apply; the guard never answers `allow` | `{"permission":"allow"}` | no output, exit 0 |
| warn | `systemMessage` plus `additionalContext`, exit 0 | `allow` with `user_message` / `agent_message` | no output |
| ask | `permissionDecision: "ask"` with the reason, exit 0. In `bypassPermissions` / `dontAsk` mode it is a deny instead | `{"permission":"ask", …}` | **deny**: Codex PreToolUse has no `ask` yet, so the reason says a human must run it |
| deny | `permissionDecision: "deny"` with the reason on stdout, the reason on stderr, **exit 2** | `{"permission":"deny","user_message":…,"agent_message":…}`, exit 0 | reason on stderr, **exit 2** |

The reason the agent reads names the rule code, what the command does, the
target and the fix, and asks the agent not to retry the operation in another
form. For example:

```
vericto guard blocked this command:
- [VG-101] prisma migrate reset drops the database and re-applies every migration. Target: db.prod.acme.io/app (production, from DATABASE_URL in .env). Fix: Run it only against a disposable local database (check DATABASE_URL first), or ask the user to run it.
If the fix fits what the user asked for, use it. Do not retry the same operation in another form (another tool, a script, a different spelling); if the user wants it run as is, tell them what it does and let them run it themselves.
```

### Failure behaviour (fail open or closed)

- **Hook input that cannot be read** (a format change, invalid JSON): if the raw
  text contains an obviously destructive operation (`DROP TABLE`, `TRUNCATE`,
  `migrate reset`, `db:drop`…), it is denied as `VG-901`. Otherwise it is allowed
  with a note. A format change must not block every command, and it must not let
  the obvious ones through.
- **A detector bug** (panic): the same fallback.
- **Invalid `[guard]` section**: the defaults apply (the strictest reading), and
  the hook says so on stderr.
- **The CLI missing** behind the Claude plugin: allowed with a visible warning
  (above); `VERICTO_GUARD_REQUIRE_CLI=1` blocks instead.
- **Cursor**: `install` sets `"failClosed": true`, so a crash or timeout of the
  hook blocks the command instead of letting it run. This is Cursor's
  recommendation for security hooks. `--fail-open` leaves it out. If you remove
  the CLI, run `vericto guard uninstall` first.
- **Codex** has no fail-closed option: a timeout or crash lets the tool run.
  The guard answers in milliseconds and always exits `0` or `2`.

## Configuration (`.vericto.toml`)

The guard reads the `[guard]` section of the nearest `.vericto.toml` at or above
the command's working directory, up to the repository root. It is the same file
`vericto check` reads. Every key is optional:

```toml
[guard]
mode = "block"            # block | ask | warn
high_sql = "ask"          # engine High findings (DROP COLUMN, RENAME, GRANT…): deny | ask | warn | allow
allow_local = false       # destructive ops whose every target is local (localhost, a socket, a file,
                          # *.local, a docker service name): warn instead of deny/ask
unverified_sql = "allow"  # SQL the guard cannot read (`gen | psql`, `-c "$(cat x)"`): allow | ask | deny
                          # (asked on production whatever this says)
prod_hosts = ["*.rds.amazonaws.com", "db-main.internal"]   # extra production patterns (globs)
local_hosts = ["devdb.acme.io"]                            # hosts treated as local
default_prod_patterns = true   # `prod`, `production`, `prd`, `live` (or prod2…) as a host or database-name token
log = true
log_sql = "redacted"      # redacted | hash | none
# log_path = "/var/log/vericto-guard.jsonl"
hard = false              # hard mode's deny rules (VG-7xx) for this project; see "Hard mode"

[guard.checks]            # turn a pack off
sql = true
mcp = true
orm = true
platform = true
prod_context = true

[[guard.allow]]           # `reason` is required; `rule` and/or `command` (globs with *)
rule = "VG-101"
command = "pnpm prisma migrate reset --force*"
reason = "the e2e suite resets its throwaway database"
# prod = true             # also on production targets (off by default)
```

Unknown keys are an error, so a typo does not silently turn a check off. When the
section cannot be read, the defaults apply.

A SQL file under `migrations/`, `migration/` or `migrate/`, a Flyway or
golang-migrate file name, or a file in `migration_paths` is read as a migration.
This is the same rule `vericto check` uses. Its schema DDL (`DROP TABLE`,
`ALTER TABLE…`) is then asked about rather than denied. TRUNCATE and DROP
SCHEMA / DATABASE are never softened.

## The decision log

Every hook call that found something is appended to a local JSON Lines file: the
time, agent, verdict, codes, targets (host and database name only) and the
command. The command is stored redacted: passwords in URLs, `PASSWORD=`,
`TOKEN=`, `SECRET=` and `KEY=` assignments, `-p<password>` and string literals
are removed, and the result is truncated to 500 characters.

- **Where**: `VERICTO_GUARD_LOG`, else `log_path`, else
  `~/.local/state/vericto/guard.jsonl` on Linux,
  `~/Library/Application Support/vericto/guard.jsonl` on macOS, or
  `%LOCALAPPDATA%\vericto\guard.jsonl` on Windows.
- **Rotation**: past 10 MiB the file becomes `guard.jsonl.1`.
- **Read it**: `vericto guard log` shows the last 20 decisions (`-n`,
  `--format json`).

Nothing is uploaded.

## Rules

Engine rules (`VERICTO-NNN`, the 42 standard rules of `vericto check --offline`)
apply to SQL. The guard's own rules:

| Code | Severity | What |
|---|---|---|
| VG-101 | critical | `prisma migrate reset` |
| VG-102 / 103 | critical | `prisma db push --force-reset` / `--accept-data-loss` |
| VG-106 / 107 | critical / medium | `drizzle-kit push --force` / `drizzle-kit drop` |
| VG-111 | critical | `rails`/`rake` `db:drop`, `db:reset`, `db:schema:load`, `db:structure:load`, `db:migrate:reset`, `db:purge`, `db:truncate_all`, `db:seed:replant` (and `:<db>` variants; `db:test:*` excluded) |
| VG-112 / 113 | medium | `db:rollback`, `db:migrate:down|redo`, `db:setup`, `db:fixtures:load` / `rails runner` with `delete_all`, `destroy_all`, `drop_table` |
| VG-116 / 117 | critical / medium | `alembic` (and `flask db`) `downgrade base` / other downgrades (`--sql` excluded) |
| VG-121 / 122 / 123 | critical | `manage.py flush` / `migrate <app> zero` / `reset_db`, `reset_schema` |
| VG-124 | medium | `python -c` with `.objects.all().delete()` |
| VG-126 / 127 | critical / medium | `artisan migrate:fresh`, `migrate:reset`, `migrate:refresh`, `db:wipe` / `migrate:rollback` |
| VG-131 / 132 | critical / medium | `knex migrate:rollback --all` / `migrate:rollback`, `migrate:down` |
| VG-136 / 137 | critical / medium | `sequelize db:drop`, `db:migrate:undo:all` / `db:migrate:undo`, `db:seed:undo*` |
| VG-141 / 142 | critical / medium | `typeorm schema:drop` / `migration:revert`, `schema:sync` |
| VG-146 / 147 | critical / medium | `mikro-orm schema:drop`, `schema:fresh`, `migration:fresh` / `migration:down`, `schema:update --run` |
| VG-151 / 152 | critical / medium | `mix ecto.drop`, `ecto.reset`, `ecto.rollback --all` / `ecto.rollback` |
| VG-156 / 157 | critical / medium | `flyway clean` / `flyway undo` |
| VG-161 / 162 | critical / medium | `liquibase drop-all` / `rollback*` |
| VG-166 / 167 | critical / medium | Doctrine `database:drop --force`, `schema:drop`, `fixtures:load` (without `--append`), `migrations:migrate first` / `prev`, `schema:update --force` |
| VG-171 | critical | `dotnet ef database drop`, `database update 0` |
| VG-176 / 177 / 178 | critical / critical / medium | `sqlx database drop|reset` / `diesel database reset`, `migration revert --all` / reverts |
| VG-181 / 182 | critical / medium | `dbmate drop` / `rollback` |
| VG-183 / 184 | critical / medium | `goose reset`, `down-to 0` / `down`, `redo` |
| VG-185 / 186 | medium / critical | `migrate … down N` / `migrate drop`, `down` with no count |
| VG-187 / 189 | critical / medium | `atlas schema clean` / `--auto-approve` |
| VG-188 | medium | `sqitch revert`, `rebase` |
| VG-191 / 192 | critical / medium | `supabase db reset` / `supabase migration down` |
| VG-196 | critical | `python -c` with SQLAlchemy `drop_all()` / `drop_database()` |
| VG-201 | critical | `dropdb` |
| VG-202 | critical | `mysqladmin drop` |
| VG-203 | critical | `redis-cli` / `valkey-cli` `FLUSHALL`, `FLUSHDB` (arguments or stdin) |
| VG-204 | critical | `mongosh` `dropDatabase()`, `drop()`, `deleteMany({})`, `remove({})`, `updateMany({}, …)`, `dropAllUsers()`; MCP `delete-many` with an empty filter |
| VG-205 / 206 | critical | `pg_restore --clean -d …` / `mongorestore --drop` |
| VG-207 | medium | `dropuser` |
| VG-301…304 | critical | SQL the engine cannot parse that is destructive on its face (DROP, TRUNCATE, DELETE / UPDATE with no WHERE) |
| VG-305 | sensitive | SQL the guard cannot read (`unverified_sql`) |
| VG-401 | critical | `heroku pg:reset` |
| VG-402 | critical | delete a database or project: `neonctl projects delete`, `pscale database delete`, `turso db destroy`, `wrangler d1 delete`, `supabase projects delete`, `heroku apps:destroy` |
| VG-403 | critical | delete a cloud database instance or its backups (`aws rds|dynamodb|redshift|docdb|elasticache …delete…`, `gcloud sql|spanner|alloydb … delete`, `az … delete`) |
| VG-404 | medium | delete or reset a database branch (Neon, PlanetScale, Supabase) |
| VG-405 | medium | `docker compose down -v`, `docker volume rm <db volume>`, `docker volume prune`, `docker system prune --volumes` |
| VG-501 | sensitive | apply migrations or schema changes (`prisma migrate deploy`, `db push`, `drizzle-kit push|migrate`, `rails db:migrate`, `alembic upgrade`, `manage.py migrate`, `artisan migrate`, `flyway migrate`, `supabase db push`…) |
| VG-601 / 602 | critical / medium | MCP tools that drop or delete by name / delete a branch, an index, pause a project |
| VG-701 | hard | a direct database client: `psql`, `pg_dump`, `pg_dumpall`, `pg_restore`, `pg_basebackup`, `pgcli`, `mysql`, `mariadb`, `mysqldump`, `mariadb-dump`, `mysqlpump`, `mysqlsh`, `mysqlimport`, `mysqladmin`, `mycli`, `sqlcmd`, `usql` (also behind `sudo`, `docker exec`, `ssh`, `bash -c`…; `--version` / `--help` alone are allowed) |
| VG-702 | hard | reading a credential file: `.env`, `.env.*` (not `.example`, `.sample`, `.template`, `.dist`, `.defaults`, `.schema`), `.envrc`, `~/.pgpass`, `pgpass.conf`, `~/.my.cnf`, `~/.mylogin.cnf`, `~/.config/vericto/**`, `/run/secrets/**`, `*.vericto-backup-*` and the hard-mode backup directory; by any program but listing, permission, deletion and env-loading launchers (`ls`, `test`, `chmod`, `rm`, `echo`, `dotenv`, `docker --env-file`…), as `< file`, `source`, an MCP tool argument, or Cursor's file reads |
| VG-703 | hard | the OS credential store: `security find-*-password`, `dump-keychain`, `set-*-partition-list`, `export`; `secret-tool`; `cmdkey`, `vaultcmd`; `kwallet-query`; `keyring get|set|del`; PowerShell `Get-StoredCredential`, `PasswordVault`, `CredRead`, `Get-Secret` |
| VG-704 | hard | `vericto-proxy mcp credential set|delete`, `vericto guard uninstall`, and shell writes (`>`, `tee`, `cp`, `mv`, `rm`, `sed -i`…) to `.vericto.toml`, `.claude/settings*.json`, `.claude.json`, `.mcp.json`, `.cursor/hooks.json`, `.cursor/mcp.json`, `.codex/hooks.json`, `.codex/config.toml` |
| VG-901 | critical | hook input that cannot be read but contains a destructive operation |

The `VG-7xx` rules apply only in hard mode (`[guard] hard = true`, or the hook
run with `--hard`, which `install --hard` writes). They are denied in every
`mode` (`ask` and `warn` do not soften them, `allow_local` does not apply); only
a `[[guard.allow]]` entry with a reason opens one, for example:

```toml
[[guard.allow]]
rule = "VG-701"
command = "docker compose exec db psql*"
reason = "the throwaway compose database; the real one is only reachable through vericto-db"
```

## Limits (read this)

A hook is a guardrail, not a security boundary.

- **It runs inside the agent's own tool loop.** The agent can write a script
  and run it (`./reset.sh`, `node scripts/wipe.js`, `make reset`), call the
  database from application code or a test, or edit `.vericto.toml` to allow
  itself. The guard reads `package.json` scripts, `bash -c`, `ssh`, `docker
  exec` and the other launchers above, but not the contents of script files,
  Makefiles or programs. Deny the agent edits to `.vericto.toml` in your agent's
  permission rules if that matters to you.
- **Agents can skip hooks.** Claude Code issue
  [#84701](https://github.com/anthropics/claude-code/issues/84701) reported
  PreToolUse denies not enforced for Bash commands from Task subagents. It was
  closed as stale on 2026-10-25 with no fix referenced. The current docs say
  hooks from settings and plugins run inside subagents, but test it on your
  version. Cursor hooks fail open by default (`install` sets `failClosed`).
  Codex skips untrusted hooks, has no fail-closed option, and says some tool
  paths "can opt out of the default hook path". Other agents and plain
  terminals are not covered at all.
- **It sees text, not the database.** Production is guessed from names: host
  and database tokens, environment names, `.env` files. A production database
  named `db1.acme.io` reached through `DATABASE_URL` from a secret manager the
  guard cannot read looks "unknown", not production. Add it to `prod_hosts`.
- **Parsing limits.** Variables set by earlier commands in another shell
  session, `$(…)` output, aliases and shell functions are unknown. SQL hidden in
  them is "unverified" (allowed off production by default). The Mongo and Redis
  checks match known destructive calls, not every way to delete data.

### Hard mode: a boundary the agent cannot step over

For a real boundary, take the capability away from the agent's process instead
of watching what it types:

1. **Read-only credentials.** Give the agent a database role that can only
   `SELECT` (or connect it to a read replica). Keep the owner or migration role
   out of its environment.
2. **No credentials where the agent looks.** No `DATABASE_URL` in the shell the
   agent runs in, in the project's `.env`, in `~/.pgpass` or in an MCP server's
   arguments.
3. **Vericto's MCP server holds the credential.** `vericto-proxy mcp` reads the
   URL from the OS keychain and runs every statement through the same engine,
   read-only, before it reaches the database.

`vericto guard install --hard` sets this up. See the next section.

## Hard mode (`vericto guard install --hard`)

Needs **vericto-proxy 5.2.0 or later** (the release with
`--database-url-keychain` and `vericto-proxy mcp credential`). The CLI looks on
`PATH`, then in Homebrew's (`/opt/homebrew/bin`, `/usr/local/bin`,
`/home/linuxbrew/.linuxbrew/bin`) and Cargo's bin directories, or takes
`--proxy PATH`. When it is missing or older, it prints the install or upgrade
command (`brew install vericto/tap/vericto-proxy`, `brew upgrade vericto-proxy`,
or the release installer) and stops. It never installs anything itself.

```sh
vericto guard install --hard                      # every agent found; asks before each step
vericto guard install --hard --agent claude --scope project --dry-run
vericto guard install --hard --yes --remove-plaintext   # no questions (CI images, scripts)
vericto guard install --hard --name shop          # an entry you stored yourself
vericto guard status                              # hard mode per agent, the role check, what is still exposed
vericto guard uninstall --hard [--delete-credential]
```

What `install --hard` does, in order:

1. **Finds the credentials an agent can read**: PostgreSQL, MySQL and MariaDB
   URLs in the project's `.env`, `.env.*` and `.envrc` (templates such as
   `.env.example` are skipped), in the environment, in the agents' MCP servers
   (Claude Code `.mcp.json` and `~/.claude.json`, including this project's
   entry; Cursor `.cursor/mcp.json` and `~/.cursor/mcp.json`; Codex
   `~/.codex/config.toml` and `.codex/config.toml`), in the URL files of
   `vericto-proxy mcp --database-url-file` servers, in `~/.pgpass` (or
   `PGPASSFILE`) and in `~/.my.cnf`. It also reports `~/.mylogin.cnf` and older
   `*.vericto-backup-*` copies that hold a URL. Only redacted forms are shown:
   `postgresql://app:***@db.acme.io:5432/shop?sslmode=require`. The query string
   shows only known-safe keys (`sslmode`, `connect_timeout`…), never a password.
2. **Moves the chosen ones into the OS keychain.** With your confirmation (or
   `--yes`), the URL is written to the stdin of `vericto-proxy mcp credential set
   <name>`, never to a command line, a file or a log. The name defaults to the
   database name (`--name` to choose). Then `vericto-proxy mcp credential test
   <name> --require-read-only` connects and checks the role:
   - **read-only**: continue;
   - **can write, or not verified** (exit 3): the reasons and the SQL for a
     read-only role (PostgreSQL or MySQL) are printed, the entry this run created
     is deleted again, and nothing is configured for it. `--allow-write-role`
     configures it anyway, without `--require-read-only`. **That is not hard
     mode**, and `status` says so;
   - **unreachable or login refused** (exit 4): the run stops and deletes what it
     stored. `--allow-unreachable` configures it anyway: the server keeps
     `--require-read-only`, so it checks the role when it starts and refuses to
     run otherwise.
3. **Configures each agent**: an MCP server `vericto-db` (`vericto-db-<name>`
   with several credentials) that runs
   `<absolute path>/vericto-proxy mcp --database-url-keychain <name> --require-read-only`,
   in `~/.claude.json` / `.mcp.json`, `~/.cursor/mcp.json` / `.cursor/mcp.json`,
   or `config.toml` (`[mcp_servers.vericto-db]`). The guard hook is installed with
   `--hard` (Cursor also gets `beforeReadFile`, so its file reads are checked),
   and Claude Code gets `permissions.deny` rules: the database clients
   (`Bash(psql:*)`…), the credential files (`Read(**/.env)`, `Read(**/.env.*)`,
   `Read(~/.pgpass)`…), the keychain commands, `vericto-proxy mcp credential
   set|delete`, `vericto guard uninstall`, `Edit`/`Write` of `.vericto.toml`, and
   the backup directory. Merges keep other servers, settings and key order; a
   second run changes nothing; files that are not valid JSON or TOML are left
   alone.
4. **Offers to take the plaintext out**, one file at a time, only with your
   consent (`--remove-plaintext` when nothing can be asked): the `.env` line, the
   `~/.pgpass` line or the `~/.my.cnf` `password` line becomes a comment that
   points here, and an MCP server entry that embeds the URL is removed (JSON has
   no comments). Programs that read the URL from those files (your app, Prisma,
   `psql` through `~/.pgpass`) stop finding it. Give them the URL another way,
   outside the agent's reach. A URL in the environment, a URL file and
   `~/.mylogin.cnf` are listed for you to remove; the CLI does not change them.

**Backups.** In hard mode every file is copied before it changes into
`<state dir>/vericto/guard-backups` (`~/.local/state` on Linux,
`~/Library/Application Support` on macOS, `%LOCALAPPDATA%` on Windows;
`VERICTO_GUARD_BACKUP_DIR` overrides it). The directory is `0700` and the copies
are `0600`. They are never next to the file: a `.env.vericto-backup-…` in the
project would be one more copy the agent and `git add` can reach. File
permissions are kept (`~/.pgpass` stays `0600`).

**`status`** shows, per agent and scope: the MCP entry and the keychain entry it
reads, whether it requires a read-only role, whether the proxy binary exists,
whether the hook runs with `--hard`, and how many of the deny rules are in place.
It then runs `credential test <name> --require-read-only` with the entry's own
binary (20 s timeout; `--no-test` skips it), and shows **read-only (verified)**,
**can write**, **unverified**, **unreachable** or **no such keychain entry**.
Last, it lists what is still exposed (redacted).

**`uninstall --hard`** removes the `vericto-db` entries and the deny rules, and
puts the hook back without `--hard`. The plain guard stays: `vericto guard
uninstall` removes it. It asks before it deletes each keychain entry
(`--delete-credential` when nothing can be asked). It does **not** write the
plaintext URLs back: the backups hold them, and you copy back what you need.
A deny rule identical to one of hard mode's is removed even if you had added it
yourself; the diff shows it.

**After install**: restart the agent; in Codex, run `/hooks` and trust the
changed hook. Claude Code asks you to approve a project's `.mcp.json` server the
first time. A project-scope install writes this machine's proxy path into
`.mcp.json`, so teammates on other machines need their own install. Linked mode
(`VERICTO_API_KEY`, `VERICTO_DATABASE_ID`) goes in the entry's `env`, which
install keeps.

### Threat model and honest limits

Hard mode defends against an agent, or a prompt injection steering it, that
looks for a credential where agents find one (`.env`, `DATABASE_URL`,
`~/.pgpass`, `~/.my.cnf`, the MCP configuration, a URL file, the keychain CLI)
and runs SQL around Vericto with `psql`, `mysql` or `pg_dump`. It also defends
against a write that gets past the statement-class check and the read-only
transaction, because the role cannot write.

It is **not an OS security boundary**. In stdio mode the server runs as your OS
user, and so does the agent:

| Platform | Who can read the keychain entry without a prompt |
|---|---|
| macOS Keychain | The `vericto-proxy` binary that created it. Another program of the same user (`security find-generic-password -w`, a script) gets a system prompt you must approve; clicking *Always Allow* removes that barrier. After a proxy upgrade the new binary prompts once. |
| Windows Credential Manager | Any process of the same user, without a prompt. It keeps the URL out of files and the environment, not out of your processes. |
| Linux Secret Service (GNOME Keyring, KWallet) | Any process of the same user while the keyring is unlocked (normally the whole desktop session), without a prompt. Needs `secret-tool` (`libsecret-tools` on Debian and Ubuntu, `libsecret` on Fedora and Arch). Servers and containers have no Secret Service: use `vericto-proxy mcp --database-url-file` (0600) there. |

Also:

- The deny rules name the common clients and the obvious reads. A determined
  agent with a shell can still write a script, use another client or a language
  driver, or read the keychain through an API (Windows and Linux, no prompt).
  The guard does not read script contents.
- Programs that load `.env` themselves (your app, Prisma, Next.js, `dotenv --`)
  still can. That is why install offers to take the URL out of the file.
- The agent can run `vericto-proxy mcp --database-url-keychain <name>` itself.
  It gets nothing more than `execute_sql`.
- Claude Code's `Read(**/.env.*)` rule also hides `.env.example` from Claude's
  Read tool. Claude rules have no exceptions. `cat .env.example` is allowed.
- Hooks can be skipped (see "Limits"). The read-only role is what holds then.
- **For strict isolation**, run the server as a different OS user (the agent's
  user cannot read that user's keychain or files), in a container, or on another
  host over Streamable HTTP, with the database's network open to the server
  only. See vericto-proxy's docs/MCP.md, "Set up Streamable HTTP for a team".

## Sources (checked 2026-11-15)

- Claude Code hooks: <https://code.claude.com/docs/en/hooks> (PreToolUse input,
  `hookSpecificOutput.permissionDecision`, exit code 2, matchers, subagents,
  `${CLAUDE_PLUGIN_ROOT}`).
- Claude Code plugins and marketplaces:
  <https://code.claude.com/docs/en/plugins/manifest-reference>,
  <https://code.claude.com/docs/en/plugins/components>,
  <https://code.claude.com/docs/en/plugins/create-marketplace>,
  <https://code.claude.com/docs/en/plugins/marketplace-reference>. Both manifests
  in this repository pass `claude plugin validate --strict`.
- Cursor hooks: <https://cursor.com/docs/hooks> (`hooks.json` `version: 1`,
  `beforeShellExecution`, `beforeMCPExecution` with `tool_input` as a JSON
  string, `permission` / `user_message` / `agent_message`, exit 2, `failClosed`).
- Codex hooks: <https://learn.chatgpt.com/docs/hooks.md> (`hooks.json` /
  `[hooks]`, PreToolUse matcher `Bash` covering shell and unified exec, deny via
  `permissionDecision` or exit 2 with stderr, `ask` not supported yet, the trust
  review with `/hooks`). Rules and approvals:
  <https://learn.chatgpt.com/docs/agent-configuration/rules.md>,
  <https://learn.chatgpt.com/docs/agent-approvals-security.md>.
