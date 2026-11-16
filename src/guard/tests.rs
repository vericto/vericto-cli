// SPDX-FileCopyrightText: 2026 Vericto S.A.S.
// SPDX-License-Identifier: AGPL-3.0-only

//! Detector and policy tests: one table per pack, false-positive traps
//! included, then production context, policy settings, MCP calls and the
//! agents' hook formats.

use std::collections::HashMap;
use std::path::Path;

use serde_json::{json, Value};

use super::config::{self, GuardConfig, Loaded};
use super::hook::{self, Agent};
use super::*;

/// A project directory with a few files the commands read.
struct Project {
    dir: tempfile::TempDir,
}

impl Project {
    fn new() -> Project {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join(".git")).unwrap();
        std::fs::write(
            dir.path().join("drop.sql"),
            "BEGIN;\nDROP TABLE users;\nCOMMIT;\n",
        )
        .unwrap();
        std::fs::write(
            dir.path().join("select.sql"),
            "SELECT id FROM users WHERE id = 1;\n",
        )
        .unwrap();
        std::fs::create_dir_all(dir.path().join("db/migrations")).unwrap();
        std::fs::write(
            dir.path().join("db/migrations/002_drop_old.sql"),
            "DROP TABLE old_users;\n",
        )
        .unwrap();
        std::fs::write(
            dir.path().join("wipe.js"),
            "db.getSiblingDB('app').dropDatabase()\n",
        )
        .unwrap();
        std::fs::write(
            dir.path().join("package.json"),
            r#"{"scripts": {
                "db:reset": "prisma migrate reset --force",
                "db:nuke": "psql -c 'DROP SCHEMA public CASCADE'",
                "db:migrate": "prisma migrate dev",
                "build": "tsc"
            }}"#,
        )
        .unwrap();
        Project { dir }
    }
    fn path(&self) -> &Path {
        self.dir.path()
    }
    fn write(&self, name: &str, text: &str) {
        std::fs::write(self.dir.path().join(name), text).unwrap();
    }
    fn loaded(&self, toml: &str) -> Loaded {
        if !toml.is_empty() {
            self.write(".vericto.toml", toml);
        }
        let l = config::load(self.path());
        assert!(l.error.is_none(), "{:?}", l.error);
        l
    }
}

fn run_with(p: &Project, loaded: &Loaded, env: &HashMap<&str, &str>, cmd: &str) -> Decision {
    let lookup = |k: &str| env.get(k).map(|v| v.to_string());
    evaluate(&Action::Shell(cmd.to_string()), p.path(), loaded, &lookup)
}

fn run(cmd: &str) -> Decision {
    let p = Project::new();
    let l = p.loaded("");
    run_with(&p, &l, &HashMap::new(), cmd)
}

fn codes(d: &Decision) -> Vec<String> {
    d.deciding()
        .iter()
        .map(|a| a.finding.code.clone())
        .collect()
}

/// `(command, verdict, code the verdict comes from (prefix match))`.
fn check_table(rows: &[(&str, Verdict, &str)]) {
    let p = Project::new();
    let l = p.loaded("");
    let env = HashMap::new();
    let mut failures = Vec::new();
    for (cmd, want, code) in rows {
        let d = run_with(&p, &l, &env, cmd);
        let cs = codes(&d);
        let code_ok = code.is_empty() || cs.iter().any(|c| c.starts_with(code));
        if d.verdict != *want || !code_ok {
            failures.push(format!(
                "{cmd:?}: got {:?} {cs:?}, want {want:?} {code}",
                d.verdict
            ));
        }
    }
    assert!(
        failures.is_empty(),
        "{} failures:\n{}",
        failures.len(),
        failures.join("\n")
    );
}

use Verdict::{Allow, Ask, Deny, Warn};

#[cfg(feature = "offline")]
#[test]
fn sql_clients_destructive() {
    check_table(&[
        ("psql -c \"DROP TABLE users\"", Deny, "VERICTO-010"),
        ("psql -tAc \"TRUNCATE orders\"", Deny, "VERICTO-011"),
        ("psql \"$DATABASE_URL\" -c 'DELETE FROM users'", Deny, "VERICTO-001"),
        ("PGPASSWORD=x psql -h localhost -U postgres -d app -c \"UPDATE users SET role='admin'\"", Deny, "VERICTO-0"),
        ("psql --command=\"DROP SCHEMA public CASCADE\"", Deny, "VERICTO-012"),
        ("psql app <<'SQL'\nBEGIN;\nDELETE FROM accounts;\nCOMMIT;\nSQL", Deny, "VERICTO-001"),
        ("echo \"DROP DATABASE prod\" | psql", Deny, "VERICTO-01"),
        ("printf 'TRUNCATE t;' | psql -d app", Deny, "VERICTO-011"),
        ("psql <<< \"DELETE FROM t\"", Deny, "VERICTO-001"),
        ("cat <<EOF | psql\nDROP TABLE x;\nEOF", Deny, "VERICTO-010"),
        ("psql -f drop.sql", Deny, "VERICTO-010"),
        ("psql < drop.sql", Deny, "VERICTO-010"),
        ("cat drop.sql | psql app", Deny, "VERICTO-010"),
        ("cat > /tmp/vg-test-x.sql <<'EOF'\nDROP TABLE t;\nEOF\npsql -f /tmp/vg-test-x.sql", Deny, "VERICTO-010"),
        ("bash -c \"psql -c 'DROP TABLE t'\"", Deny, "VERICTO-010"),
        ("sh -lc 'psql -c \"TRUNCATE t\"'", Deny, "VERICTO-011"),
        ("ssh db1 \"psql -c 'DROP TABLE t'\"", Deny, "VERICTO-010"),
        ("docker exec -it pg psql -U postgres -c \"DROP TABLE t\"", Deny, "VERICTO-010"),
        ("docker compose exec -T db psql -U postgres -c 'TRUNCATE t'", Deny, "VERICTO-011"),
        ("kubectl exec -it pg-0 -- psql -c \"DROP TABLE t\"", Deny, "VERICTO-010"),
        ("sudo -u postgres psql -c \"DROP DATABASE app\"", Deny, "VERICTO-01"),
        ("env PGHOST=x psql -c 'DELETE FROM t'", Deny, "VERICTO-001"),
        ("cd app && psql -c 'DROP TABLE t'", Deny, "VERICTO-010"),
        ("true; psql -c 'DROP TABLE t' || echo fail", Deny, "VERICTO-010"),
        ("(psql -c 'DROP TABLE t')", Deny, "VERICTO-010"),
        ("echo $(psql -c \"DROP TABLE t\")", Deny, "VERICTO-010"),
        ("psql -c \"SELECT 1; DROP TABLE t\"", Deny, "VERICTO-010"),
        ("psql -c \"DELETE FROM t WHERE 1=1\"", Deny, "VERICTO-003"),
        ("psql -c \"DROP TABLE \\$T\"", Deny, "VG-301"),
        ("mysql -u root -e \"DROP DATABASE app\"", Deny, "VERICTO-01"),
        ("mysql -uroot -psecret app -e 'TRUNCATE TABLE logs'", Deny, "VERICTO-011"),
        ("mysql app < drop.sql", Deny, "VERICTO-010"),
        ("mariadb -e \"DELETE FROM users\"", Deny, "VERICTO-001"),
        ("mysql --execute=\"UPDATE users SET a=1\"", Deny, "VERICTO-0"),
        ("sqlite3 app.db \"DROP TABLE users\"", Deny, "VERICTO-010"),
        ("sqlite3 app.db 'DELETE FROM users'", Deny, "VERICTO-001"),
        ("sqlite3 -cmd \"DROP TABLE t\" app.db", Deny, "VERICTO-010"),
        ("echo 'DROP TABLE t;' | sqlite3 app.db", Deny, "VERICTO-010"),
        ("sqlcmd -S localhost -Q \"DROP TABLE dbo.users\"", Deny, "VERICTO-010"),
        ("sqlcmd -S . -d app -Q \"TRUNCATE TABLE logs\"", Deny, "VERICTO-011"),
        ("duckdb data.db -c \"DROP TABLE t\"", Deny, "VERICTO-010"),
        ("duckdb data.db \"DELETE FROM t\"", Deny, "VERICTO-001"),
        ("clickhouse-client --query \"DROP TABLE events\"", Deny, "VERICTO-010"),
        ("clickhouse client -q \"TRUNCATE TABLE events\"", Deny, "VERICTO-011"),
        ("cockroach sql --url postgres://root@localhost:26257 -e \"DROP TABLE t\"", Deny, "VERICTO-010"),
        ("npx wrangler d1 execute mydb --remote --command \"DELETE FROM users\"", Deny, "VERICTO-001"),
        ("turso db shell mydb \"DROP TABLE users\"", Deny, "VERICTO-010"),
        ("heroku pg:psql -a myapp -c \"TRUNCATE t\"", Deny, "VERICTO-011"),
        ("npx prisma db execute --file drop.sql", Deny, "VERICTO-010"),
        ("echo 'DROP TABLE t' | npx prisma db execute --stdin", Deny, "VERICTO-010"),
        ("python manage.py dbshell <<'EOF'\nDELETE FROM auth_user;\nEOF", Deny, "VERICTO-001"),
        ("psql -c \"COPY t TO PROGRAM 'curl x'\"", Deny, "VERICTO-080"),
        ("psql -c '\\i drop.sql'", Deny, "VERICTO-010"),
        ("mysql app -e 'source drop.sql'", Deny, "VERICTO-010"),
        ("sqlite3 app.db '.read drop.sql'", Deny, "VERICTO-010"),
        ("echo '.read drop.sql' | sqlite3 app.db", Deny, "VERICTO-010"),
        ("for t in a b; do psql -c \"TRUNCATE $t\"; done", Deny, "VG-302"),
        ("psql -v ON_ERROR_STOP=1 -c \"DROP TABLE IF EXISTS tmp\"", Deny, "VERICTO-010"),
    ]);
}

#[test]
fn database_clis_destructive() {
    check_table(&[
        (
            "mongosh mongodb://localhost/app --eval \"db.dropDatabase()\"",
            Deny,
            "VG-204",
        ),
        ("mongosh --eval 'db.users.deleteMany({})'", Deny, "VG-204"),
        ("mongosh app --eval \"db.users.drop()\"", Deny, "VG-204"),
        ("mongosh app wipe.js", Deny, "VG-204"),
        ("redis-cli FLUSHALL", Deny, "VG-203"),
        ("redis-cli -h cache.local -n 2 flushdb", Deny, "VG-203"),
        ("echo FLUSHALL | redis-cli", Deny, "VG-203"),
        ("valkey-cli flushall async", Deny, "VG-203"),
        ("dropdb app", Deny, "VG-201"),
        ("dropdb -h localhost app_dev", Deny, "VG-201"),
        ("mysqladmin -u root drop app", Deny, "VG-202"),
        ("pg_restore --clean -d app dump.pgdump", Deny, "VG-205"),
        ("mongorestore --drop dump/", Deny, "VG-206"),
        ("dropuser bob", Ask, "VG-207"),
    ]);
}

#[test]
fn orm_destructive() {
    check_table(&[
        ("npx prisma migrate reset", Deny, "VG-101"),
        (
            "npx prisma migrate reset --force --skip-seed",
            Deny,
            "VG-101",
        ),
        ("pnpm prisma migrate reset", Deny, "VG-101"),
        ("yarn prisma db push --force-reset", Deny, "VG-102"),
        ("bunx prisma db push --accept-data-loss", Deny, "VG-103"),
        ("pnpm exec prisma migrate reset", Deny, "VG-101"),
        ("npx prisma@6 migrate reset", Deny, "VG-101"),
        ("npx -y prisma migrate reset --force", Deny, "VG-101"),
        ("./node_modules/.bin/prisma migrate reset", Deny, "VG-101"),
        (
            "dotenv -e .env.test -- npx prisma migrate reset",
            Deny,
            "VG-101",
        ),
        ("npx drizzle-kit push --force", Deny, "VG-106"),
        (
            "pnpm drizzle-kit push --force --config drizzle.config.ts",
            Deny,
            "VG-106",
        ),
        ("rails db:drop", Deny, "VG-111"),
        ("bin/rails db:reset", Deny, "VG-111"),
        ("bundle exec rake db:schema:load", Deny, "VG-111"),
        ("rake db:migrate:reset", Deny, "VG-111"),
        ("rails db:purge", Deny, "VG-111"),
        ("RAILS_ENV=test rails db:drop", Deny, "VG-111"),
        ("rails db:drop:primary", Deny, "VG-111"),
        ("rails db:drop db:create db:migrate", Deny, "VG-111"),
        ("rails db:seed:replant", Deny, "VG-111"),
        ("alembic downgrade base", Deny, "VG-116"),
        ("uv run alembic downgrade base", Deny, "VG-116"),
        (
            "poetry run alembic -c alembic.ini downgrade base",
            Deny,
            "VG-116",
        ),
        ("python -m alembic downgrade base", Deny, "VG-116"),
        ("flask db downgrade base", Deny, "VG-116"),
        ("python manage.py flush --noinput", Deny, "VG-121"),
        ("python3 manage.py migrate users zero", Deny, "VG-122"),
        ("./manage.py reset_db --noinput", Deny, "VG-123"),
        ("django-admin flush", Deny, "VG-121"),
        ("php artisan migrate:fresh --seed", Deny, "VG-126"),
        ("php artisan db:wipe --force", Deny, "VG-126"),
        ("php artisan migrate:refresh", Deny, "VG-126"),
        ("php artisan migrate:reset", Deny, "VG-126"),
        ("npx knex migrate:rollback --all", Deny, "VG-131"),
        ("npx sequelize-cli db:drop", Deny, "VG-136"),
        ("npx sequelize db:migrate:undo:all", Deny, "VG-136"),
        (
            "npx typeorm schema:drop -d src/data-source.ts",
            Deny,
            "VG-141",
        ),
        ("npx typeorm-ts-node-commonjs schema:drop", Deny, "VG-141"),
        ("npx mikro-orm schema:drop --run", Deny, "VG-146"),
        ("npx mikro-orm migration:fresh", Deny, "VG-146"),
        ("mix ecto.drop", Deny, "VG-151"),
        ("mix ecto.reset", Deny, "VG-151"),
        ("MIX_ENV=dev mix ecto.rollback --all", Deny, "VG-151"),
        ("mix do ecto.drop, ecto.create", Deny, "VG-151"),
        ("flyway clean", Deny, "VG-156"),
        (
            "flyway -url=jdbc:postgresql://localhost/app clean",
            Deny,
            "VG-156",
        ),
        ("docker run --rm flyway/flyway clean", Deny, "VG-156"),
        ("liquibase drop-all", Deny, "VG-161"),
        (
            "liquibase dropAll --url=jdbc:mysql://localhost/app",
            Deny,
            "VG-161",
        ),
        (
            "php bin/console doctrine:database:drop --force",
            Deny,
            "VG-166",
        ),
        ("php bin/console doctrine:fixtures:load", Deny, "VG-166"),
        (
            "symfony console doctrine:schema:drop --force",
            Deny,
            "VG-166",
        ),
        ("dotnet ef database drop --force", Deny, "VG-171"),
        ("dotnet ef database update 0", Deny, "VG-171"),
        ("sqlx database reset -y", Deny, "VG-176"),
        ("cargo sqlx database drop", Deny, "VG-176"),
        ("diesel database reset", Deny, "VG-177"),
        ("dbmate drop", Deny, "VG-181"),
        (
            "goose postgres \"host=localhost dbname=app\" reset",
            Deny,
            "VG-183",
        ),
        (
            "migrate -path db/migrations -database postgres://localhost/app drop -f",
            Deny,
            "VG-186",
        ),
        (
            "migrate -path db/migrations -database postgres://localhost/app down",
            Deny,
            "VG-186",
        ),
        (
            "atlas schema clean -u postgres://localhost/app",
            Deny,
            "VG-187",
        ),
        ("supabase db reset --linked", Deny, "VG-191"),
        ("npx supabase db reset", Deny, "VG-191"),
        (
            "python -c \"from app import db; db.drop_all()\"",
            Deny,
            "VG-196",
        ),
        ("python -c 'Base.metadata.drop_all(engine)'", Deny, "VG-196"),
    ]);
}

#[test]
fn platform_destructive() {
    check_table(&[
        (
            "heroku pg:reset DATABASE_URL -a myapp --confirm myapp",
            Deny,
            "VG-401",
        ),
        ("neonctl projects delete abc", Deny, "VG-402"),
        ("pscale database delete app", Deny, "VG-402"),
        ("turso db destroy app --yes", Deny, "VG-402"),
        ("supabase projects delete abc", Deny, "VG-402"),
        ("wrangler d1 delete mydb", Deny, "VG-402"),
        (
            "aws rds delete-db-instance --db-instance-identifier app --skip-final-snapshot",
            Deny,
            "VG-403",
        ),
        (
            "aws dynamodb delete-table --table-name users",
            Deny,
            "VG-403",
        ),
        ("gcloud sql instances delete app-db", Deny, "VG-403"),
        (
            "az postgres flexible-server delete -g rg -n app",
            Deny,
            "VG-403",
        ),
        ("neonctl branches delete dev", Ask, "VG-404"),
        ("pscale branch delete app dev", Ask, "VG-404"),
        ("docker compose down -v", Ask, "VG-405"),
        ("docker-compose down --volumes", Ask, "VG-405"),
        ("docker volume rm app_pgdata", Ask, "VG-405"),
        ("docker system prune -a --volumes", Ask, "VG-405"),
    ]);
}

#[test]
fn launchers_and_scripts() {
    check_table(&[
        ("npm run db:reset", Deny, "VG-101"),
        ("pnpm db:reset", Deny, "VG-101"),
        ("pnpm run db:reset", Deny, "VG-101"),
        ("yarn run db:nuke", Deny, ""),
        ("bun run db:reset", Deny, "VG-101"),
        ("eval \"rails db:drop\"", Deny, "VG-111"),
        ("timeout 60 npx prisma migrate reset", Deny, "VG-101"),
        ("nohup rails db:reset &", Deny, "VG-111"),
        ("find . -name x | xargs dropdb", Allow, ""),
        (
            "cross-env NODE_ENV=test prisma migrate reset",
            Deny,
            "VG-101",
        ),
        (
            "env-cmd -f .env.test npx prisma migrate reset",
            Deny,
            "VG-101",
        ),
        ("doppler run -- npx prisma migrate reset", Deny, "VG-101"),
        ("op run --env-file=.env -- rails db:drop", Deny, "VG-111"),
        ("heroku run rails db:drop -a myapp", Deny, "VG-111"),
        ("fly ssh console -C \"bin/rails db:drop\"", Deny, "VG-111"),
        ("time nice -n 10 rake db:drop", Deny, "VG-111"),
        ("watch -n 5 redis-cli FLUSHDB", Deny, "VG-203"),
        ("npm exec -- prisma migrate reset", Deny, "VG-101"),
        ("npx -c 'prisma migrate reset --force'", Deny, "VG-101"),
        ("uvx --from alembic alembic downgrade base", Deny, "VG-116"),
        ("pipenv run python manage.py flush", Deny, "VG-121"),
        (
            "dotenvx run -f .env.local -- npx prisma migrate reset",
            Deny,
            "VG-101",
        ),
        (
            "zsh -ec 'cd api; npx prisma migrate reset --force'",
            Deny,
            "VG-101",
        ),
        ("bash <<'EOF'\nrails db:drop\nEOF", Deny, "VG-111"),
        ("npm run db:migrate", Allow, ""),
        ("npm run build", Allow, ""),
    ]);
}

#[test]
fn medium_operations_ask() {
    check_table(&[
        ("rails db:rollback STEP=3", Ask, "VG-112"),
        ("alembic downgrade -1", Ask, "VG-117"),
        ("php artisan migrate:rollback", Ask, "VG-127"),
        ("npx knex migrate:rollback", Ask, "VG-132"),
        ("npx sequelize-cli db:migrate:undo", Ask, "VG-137"),
        ("npx typeorm migration:revert", Ask, "VG-142"),
        ("mix ecto.rollback", Ask, "VG-152"),
        ("flyway undo", Ask, "VG-157"),
        ("liquibase rollback-count 1", Ask, "VG-162"),
        ("npx drizzle-kit drop", Ask, "VG-107"),
        ("supabase migration down", Ask, "VG-192"),
        ("goose down", Ask, "VG-184"),
        ("dbmate rollback", Ask, "VG-182"),
        ("diesel migration revert", Ask, "VG-178"),
        ("rails runner 'User.delete_all'", Ask, "VG-113"),
        ("python -c 'User.objects.all().delete()'", Ask, "VG-124"),
    ]);
}

#[cfg(feature = "offline")]
#[test]
fn medium_sql_asks() {
    check_table(&[
        (
            "psql -c \"ALTER TABLE users DROP COLUMN email\"",
            Ask,
            "VERICTO-015",
        ),
        (
            "psql -c \"GRANT ALL ON users TO public\"",
            Ask,
            "VERICTO-082",
        ),
        (
            "psql -c \"ALTER TABLE users RENAME TO people\"",
            Ask,
            "VERICTO-016",
        ),
        // A migration file: schema DDL is capped (asked), TRUNCATE is not.
        ("psql -f db/migrations/002_drop_old.sql", Ask, "VERICTO-010"),
    ]);
}

#[test]
fn false_positive_traps() {
    check_table(&[
        ("grep -r \"DROP TABLE\" .", Allow, ""),
        ("grep DROP schema.sql", Allow, ""),
        ("echo \"DELETE FROM users\"", Allow, ""),
        ("git commit -m \"DROP TABLE users fix\"", Allow, ""),
        ("rg 'TRUNCATE' src/", Allow, ""),
        ("cat schema.sql", Allow, ""),
        ("# psql -c \"DROP TABLE t\"", Allow, ""),
        ("echo hi # rails db:drop", Allow, ""),
        ("npx prisma migrate dev", Allow, ""),
        ("npx prisma migrate dev --name init", Allow, ""),
        ("npx prisma generate", Allow, ""),
        ("npx prisma migrate status", Allow, ""),
        ("npx prisma db pull", Allow, ""),
        ("npx prisma studio", Allow, ""),
        ("rails db:migrate", Allow, ""),
        ("rails db:test:prepare", Allow, ""),
        ("bin/rails db:create", Allow, ""),
        ("rails db:seed", Allow, ""),
        ("rails generate migration AddEmailToUsers", Allow, ""),
        ("alembic upgrade head", Allow, ""),
        (
            "alembic revision --autogenerate -m \"drop old table\"",
            Allow,
            "",
        ),
        ("alembic downgrade -1 --sql", Allow, ""),
        ("alembic history", Allow, ""),
        ("python manage.py migrate", Allow, ""),
        ("python manage.py makemigrations", Allow, ""),
        ("python manage.py sqlflush", Allow, ""),
        ("python manage.py test", Allow, ""),
        ("php artisan migrate", Allow, ""),
        ("php artisan make:migration drop_users_table", Allow, ""),
        ("npx knex migrate:latest", Allow, ""),
        ("npx knex migrate:make drop_users", Allow, ""),
        ("npx drizzle-kit generate", Allow, ""),
        ("npx drizzle-kit push", Allow, ""),
        ("npx sequelize-cli db:migrate", Allow, ""),
        ("npx typeorm migration:generate src/migrations/x", Allow, ""),
        ("mix ecto.migrate", Allow, ""),
        ("mix test", Allow, ""),
        ("flyway info", Allow, ""),
        ("flyway migrate", Allow, ""),
        ("liquibase update", Allow, ""),
        ("liquibase status", Allow, ""),
        ("supabase db dump -f dump.sql", Allow, ""),
        ("supabase start", Allow, ""),
        ("supabase db diff", Allow, ""),
        ("supabase db push", Allow, ""),
        ("psql -c \"SELECT * FROM users\"", Allow, ""),
        ("psql -c \"\\dt\"", Allow, ""),
        (
            "psql -c \"DELETE FROM sessions WHERE expires_at < now()\"",
            Allow,
            "",
        ),
        (
            "psql -c \"UPDATE users SET name = 'x' WHERE id = 1\"",
            Allow,
            "",
        ),
        ("psql -c \"SELECT 'DROP TABLE users'\"", Allow, ""),
        ("psql -c \"CREATE TABLE t (id int)\"", Allow, ""),
        ("psql -f select.sql", Allow, ""),
        ("psql", Allow, ""),
        ("psql -l", Allow, ""),
        ("mysql -e \"SELECT COUNT(*) FROM orders\"", Allow, ""),
        ("mysql -e 'SHOW TABLES'", Allow, ""),
        ("sqlite3 app.db .tables", Allow, ""),
        ("sqlite3 app.db \"SELECT * FROM t\"", Allow, ""),
        ("redis-cli GET key", Allow, ""),
        ("redis-cli KEYS 'session:*'", Allow, ""),
        ("redis-cli -h prod-cache.acme.io INFO", Allow, ""),
        ("mongosh --eval \"db.users.find()\"", Allow, ""),
        (
            "mongosh --eval 'db.users.deleteMany({status: \"x\"})'",
            Allow,
            "",
        ),
        ("docker compose down", Allow, ""),
        ("docker compose up -d db", Allow, ""),
        (
            "docker exec pg pg_dump -U postgres app > dump.sql",
            Allow,
            "",
        ),
        ("pg_dump --clean app > dump.sql", Allow, ""),
        ("pg_restore -l dump.pgdump", Allow, ""),
        ("pg_restore -d app dump.pgdump", Allow, ""),
        ("dropdb --help", Allow, ""),
        ("npm test", Allow, ""),
        ("ls -la", Allow, ""),
        ("aws rds describe-db-instances", Allow, ""),
        ("gcloud sql instances list", Allow, ""),
        ("kubectl get pods", Allow, ""),
        ("ssh host ls", Allow, ""),
        (
            "cat <<'EOF' > notes.md\nDROP TABLE explanation\nEOF",
            Allow,
            "",
        ),
        ("git log --grep=\"db:drop\"", Allow, ""),
        ("echo \"rails db:drop\" >> TODO.md", Allow, ""),
        ("python -c \"print('drop_all')\"", Allow, ""),
        (
            "migrate create -ext sql -dir db/migrations add_users",
            Allow,
            "",
        ),
        ("docker volume ls", Allow, ""),
        ("docker volume rm node_modules_cache", Allow, ""),
        ("heroku logs -a myapp", Allow, ""),
        ("psql -h db.prod.acme.io -c \"SELECT 1\"", Allow, ""),
        ("vim db/migrations/002_drop_old.sql", Allow, ""),
        ("sed -i 's/DROP TABLE/-- DROP TABLE/' x.sql", Allow, ""),
        ("printf 'DROP TABLE x' > x.sql", Allow, ""),
        ("node -e \"console.log('prisma migrate reset')\"", Allow, ""),
        ("cargo test drop_table", Allow, ""),
        ("pytest -k flush", Allow, ""),
        ("make db-reset-docs", Allow, ""),
        ("npx eslint src/db/reset.ts", Allow, ""),
        ("dbmate new drop_users", Allow, ""),
        ("goose create drop_users sql", Allow, ""),
        ("diesel migration generate drop_users", Allow, ""),
        ("sqlx migrate add drop_users", Allow, ""),
        ("dotnet ef migrations add DropUsers", Allow, ""),
        ("atlas migrate diff --env local", Allow, ""),
    ]);
}

#[test]
fn production_context() {
    let p = Project::new();
    let l = p.loaded("");
    let none = HashMap::new();
    // A production host makes a medium finding a deny.
    let d = run_with(
        &p,
        &l,
        &none,
        "psql -h db.prod.acme.io -c \"ALTER TABLE users DROP COLUMN x\"",
    );
    #[cfg(feature = "offline")]
    {
        assert_eq!(d.verdict, Deny);
        assert!(d.deciding()[0].prod);
    }
    let _ = d;
    // Applying migrations: allowed on a dev database, asked on production.
    let d = run_with(
        &p,
        &l,
        &none,
        "DATABASE_URL=postgres://u:p@db.prod.acme.io/app npx prisma migrate deploy",
    );
    assert_eq!(d.verdict, Ask);
    let t = &d.deciding()[0].finding.targets[0];
    assert_eq!(t.host, "db.prod.acme.io");
    assert!(!format!("{t:?}").contains(":p@"));
    assert_eq!(
        run_with(
            &p,
            &l,
            &none,
            "DATABASE_URL=postgres://localhost/app npx prisma migrate deploy"
        )
        .verdict,
        Allow
    );
    assert_eq!(
        run_with(&p, &l, &none, "RAILS_ENV=production rails db:migrate").verdict,
        Ask
    );
    assert_eq!(
        run_with(&p, &l, &none, "rails db:migrate RAILS_ENV=production").verdict,
        Ask
    );
    assert_eq!(
        run_with(&p, &l, &none, "bin/rails db:migrate -e production").verdict,
        Ask
    );
    assert_eq!(
        run_with(&p, &l, &none, "php artisan migrate --env=production").verdict,
        Ask
    );
    assert_eq!(
        run_with(&p, &l, &none, "MIX_ENV=prod mix ecto.migrate").verdict,
        Ask
    );
    assert_eq!(
        run_with(
            &p,
            &l,
            &none,
            "python manage.py migrate --settings=app.settings.production"
        )
        .verdict,
        Ask
    );
    assert_eq!(
        run_with(&p, &l, &none, "alembic -n production upgrade head").verdict,
        Ask
    );
    assert_eq!(
        run_with(
            &p,
            &l,
            &none,
            "npx sequelize-cli db:migrate --env production"
        )
        .verdict,
        Ask
    );
    assert_eq!(
        run_with(
            &p,
            &l,
            &none,
            "doppler run -c prd -- npx prisma migrate deploy"
        )
        .verdict,
        Ask
    );
    assert_eq!(
        run_with(
            &p,
            &l,
            &none,
            "infisical run --env=prod -- rails db:migrate"
        )
        .verdict,
        Ask
    );
    assert!(
        run_with(
            &p,
            &l,
            &none,
            "rails db:drop DISABLE_DATABASE_ENVIRONMENT_CHECK=1"
        )
        .deciding()[0]
            .prod
    );
    // Medium on production: denied.
    assert_eq!(
        run_with(&p, &l, &none, "RAILS_ENV=production rails db:rollback").verdict,
        Deny
    );
    // A production env file named by the command.
    p.write(
        ".env.production",
        "DATABASE_URL=postgres://app:secret@pg.internal.acme.io/app\n",
    );
    let d = run_with(
        &p,
        &l,
        &none,
        "dotenv -e .env.production -- npx prisma migrate deploy",
    );
    assert_eq!(d.verdict, Ask);
    // Unreadable SQL to production is asked; to localhost allowed.
    assert_eq!(
        run_with(&p, &l, &none, "pg_dump src | psql -h db.prod.acme.io app").verdict,
        Ask
    );
    assert_eq!(
        run_with(&p, &l, &none, "pg_dump src | psql -h localhost app").verdict,
        Allow
    );
    // ssh / kubectl contexts.
    #[cfg(feature = "offline")]
    {
        assert_eq!(
            run_with(
                &p,
                &l,
                &none,
                "kubectl --context prod exec pg-0 -- psql -c \"ALTER TABLE t RENAME TO u\""
            )
            .verdict,
            Deny
        );
        assert_eq!(
            run_with(
                &p,
                &l,
                &none,
                "ssh prod-bastion \"psql -c 'ALTER TABLE t DROP COLUMN c'\""
            )
            .verdict,
            Deny
        );
        assert_eq!(
            run_with(&p, &l, &none, "ssh prod-bastion \"psql -c 'SELECT 1'\"").verdict,
            Allow
        );
    }
    // The agent's environment.
    let env: HashMap<&str, &str> = [("DATABASE_URL", "postgres://x:y@prod-db.acme.io:5432/app")]
        .into_iter()
        .collect();
    let d = run_with(&p, &l, &env, "npx prisma db push");
    assert_eq!(d.verdict, Ask);
    assert!(d.deciding()[0]
        .finding
        .targets
        .iter()
        .any(|t| t.source.contains("agent's environment")));
    // psql "$DATABASE_URL" resolved from the environment.
    let d = run_with(&p, &l, &env, "psql \"$DATABASE_URL\" -c 'DROP TABLE t'");
    #[cfg(feature = "offline")]
    assert!(d.deciding()[0].prod);
    let _ = d;
}

#[test]
fn project_env_file_points_at_production() {
    let p = Project::new();
    p.write(
        ".env",
        "DATABASE_URL=\"postgresql://admin:hunter2@db.production.acme.io:5432/app\"\n",
    );
    let l = p.loaded("");
    let d = run_with(&p, &l, &HashMap::new(), "npx prisma migrate reset --force");
    assert_eq!(d.verdict, Deny);
    let a = &d.deciding()[0];
    assert!(a.prod);
    let msg = d.agent_message(Deny);
    assert!(
        msg.contains("db.production.acme.io") && msg.contains("DATABASE_URL in .env"),
        "{msg}"
    );
    assert!(!msg.contains("hunter2"), "{msg}");
    // .env.local wins over .env.
    p.write(
        ".env.local",
        "DATABASE_URL=postgresql://localhost:5432/app\n",
    );
    let d = run_with(&p, &l, &HashMap::new(), "npx prisma migrate deploy");
    assert_eq!(d.verdict, Allow);
}

#[test]
fn policy_settings() {
    let none = HashMap::new();
    // mode = warn: local critical is a warning, production stays denied.
    let p = Project::new();
    let l = p.loaded("[guard]\nmode = \"warn\"\n");
    assert_eq!(
        run_with(&p, &l, &none, "npx prisma migrate reset").verdict,
        Warn
    );
    assert_eq!(
        run_with(
            &p,
            &l,
            &none,
            "DATABASE_URL=postgres://db.prod.acme.io/x npx prisma migrate reset"
        )
        .verdict,
        Deny
    );
    // mode = ask.
    let p = Project::new();
    let l = p.loaded("[guard]\nmode = \"ask\"\n");
    assert_eq!(run_with(&p, &l, &none, "rails db:drop").verdict, Ask);
    // allow_local.
    let p = Project::new();
    let l = p.loaded("[guard]\nallow_local = true\n");
    assert_eq!(
        run_with(
            &p,
            &l,
            &none,
            "DATABASE_URL=postgres://localhost/app npx prisma migrate reset"
        )
        .verdict,
        Warn
    );
    assert_eq!(
        run_with(&p, &l, &none, "npx prisma migrate reset").verdict,
        Deny,
        "unknown target is not local"
    );
    assert_eq!(
        run_with(&p, &l, &none, "npx supabase db reset").verdict,
        Warn
    );
    // allow entries need a reason and do not open production by default.
    let p = Project::new();
    let l = p.loaded("[[guard.allow]]\nrule = \"VG-101\"\nreason = \"e2e resets its throwaway db\"\n\n[[guard.allow]]\ncommand = \"rails db:reset*\"\nreason = \"seed refresh\"\nprod = true\n");
    let d = run_with(&p, &l, &none, "npx prisma migrate reset");
    assert_eq!(d.verdict, Allow);
    assert_eq!(
        d.applied[0].allowed_by.as_deref(),
        Some("e2e resets its throwaway db")
    );
    assert_eq!(
        run_with(
            &p,
            &l,
            &none,
            "DATABASE_URL=postgres://db.prod.acme.io/x npx prisma migrate reset"
        )
        .verdict,
        Deny
    );
    assert_eq!(
        run_with(&p, &l, &none, "rails db:reset RAILS_ENV=production").verdict,
        Allow
    );
    assert_eq!(run_with(&p, &l, &none, "rails db:drop").verdict, Deny);
    // Checks can be turned off.
    let p = Project::new();
    let l = p.loaded("[guard.checks]\norm = false\nplatform = false\n");
    assert_eq!(
        run_with(&p, &l, &none, "npx prisma migrate reset").verdict,
        Allow
    );
    assert_eq!(
        run_with(&p, &l, &none, "docker compose down -v").verdict,
        Allow
    );
    // prod_hosts / unverified_sql / high_sql / prod_context.
    let p = Project::new();
    let l = p.loaded("[guard]\nprod_hosts = [\"*.rds.amazonaws.com\"]\nunverified_sql = \"ask\"\nhigh_sql = \"deny\"\n");
    assert_eq!(
        run_with(
            &p,
            &l,
            &none,
            "DATABASE_URL=postgres://a.b.us-east-1.rds.amazonaws.com/x npx prisma migrate deploy"
        )
        .verdict,
        Ask
    );
    assert_eq!(
        run_with(&p, &l, &none, "gen-sql | psql -h localhost").verdict,
        Ask
    );
    #[cfg(feature = "offline")]
    assert_eq!(
        run_with(&p, &l, &none, "psql -c \"ALTER TABLE t DROP COLUMN c\"").verdict,
        Deny
    );
    let p = Project::new();
    let l = p.loaded("[guard.checks]\nprod_context = false\n");
    assert_eq!(
        run_with(&p, &l, &none, "RAILS_ENV=production rails db:migrate").verdict,
        Allow
    );
}

#[test]
fn messages_carry_code_target_and_fix() {
    let p = Project::new();
    let l = p.loaded("");
    let d = run_with(
        &p,
        &l,
        &HashMap::new(),
        "DATABASE_URL=postgres://u:pw@db.prod.acme.io/app npx prisma migrate reset",
    );
    let m = d.agent_message(Deny);
    assert!(
        m.contains("[VG-101]") && m.contains("Fix:") && m.contains("production"),
        "{m}"
    );
    assert!(!m.contains("pw@"), "{m}");
    let u = d.user_message(Deny);
    assert!(u.contains("VG-101") && u.contains("[[guard.allow]]"), "{u}");
}

// ---------------------------------------------------------------- MCP

fn mcp(server: &str, tool: &str, input: Value) -> Decision {
    let p = Project::new();
    let l = p.loaded("");
    evaluate(
        &Action::Mcp {
            server: server.into(),
            tool: tool.into(),
            input,
        },
        p.path(),
        &l,
        &|_| None,
    )
}

#[test]
fn mcp_tools() {
    #[cfg(feature = "offline")]
    {
        assert_eq!(
            mcp(
                "supabase",
                "execute_sql",
                json!({"project_id": "abc", "query": "DROP TABLE users"})
            )
            .verdict,
            Deny
        );
        assert_eq!(
            mcp("postgres", "query", json!({"sql": "DELETE FROM t"})).verdict,
            Deny
        );
        assert_eq!(
            mcp(
                "neon",
                "run_sql_transaction",
                json!({"sqlStatements": ["SELECT 1", "TRUNCATE t"]})
            )
            .verdict,
            Deny
        );
        assert_eq!(
            mcp(
                "dbhub",
                "execute_sql",
                json!({"sql": "UPDATE users SET admin = true"})
            )
            .verdict,
            Deny
        );
        assert_eq!(
            mcp("mysql", "mysql_query", json!({"sql": "DELETE FROM orders"})).verdict,
            Deny
        );
        assert_eq!(
            mcp(
                "supabase-prod",
                "execute_sql",
                json!({"query": "ALTER TABLE t DROP COLUMN c"})
            )
            .verdict,
            Deny
        );
        assert_eq!(
            mcp(
                "supabase",
                "execute_sql",
                json!({"query": "ALTER TABLE t DROP COLUMN c"})
            )
            .verdict,
            Ask
        );
        assert_eq!(
            mcp(
                "supabase",
                "apply_migration",
                json!({"name": "x", "query": "DROP TABLE t"})
            )
            .verdict,
            Deny
        );
    }
    assert_eq!(
        mcp("mysql", "mysql_query", json!({"sql": "SELECT 1"})).verdict,
        Allow
    );
    assert_eq!(
        mcp(
            "dbhub",
            "execute_sql",
            json!({"sql": "select * from t where id = 1"})
        )
        .verdict,
        Allow
    );
    assert_eq!(
        mcp(
            "supabase-prod",
            "execute_sql",
            json!({"query": "UPDATE users SET a = 1 WHERE id = 1"})
        )
        .verdict,
        Allow
    );
    // Search tools' `query` is prose.
    assert_eq!(
        mcp(
            "brave-search",
            "brave_web_search",
            json!({"query": "DROP TABLE users"})
        )
        .verdict,
        Allow
    );
    assert_eq!(
        mcp("github", "search_code", json!({"query": "TRUNCATE orders"})).verdict,
        Allow
    );
    // Destructive tools by name.
    assert_eq!(
        mcp(
            "mongodb",
            "drop-collection",
            json!({"database": "app", "collection": "users"})
        )
        .verdict,
        Deny
    );
    assert_eq!(
        mcp("mongodb", "drop-database", json!({"database": "app"})).verdict,
        Deny
    );
    assert_eq!(
        mcp("neon", "delete_project", json!({"projectId": "x"})).verdict,
        Deny
    );
    assert_eq!(
        mcp(
            "neon",
            "delete_branch",
            json!({"projectId": "x", "branchId": "y"})
        )
        .verdict,
        Ask
    );
    assert_eq!(mcp("redis", "flushdb", json!({})).verdict, Deny);
    assert_eq!(
        mcp(
            "mongodb",
            "delete-many",
            json!({"database": "app", "collection": "u", "filter": {}})
        )
        .verdict,
        Deny
    );
    assert_eq!(
        mcp(
            "mongodb",
            "delete-many",
            json!({"database": "app", "collection": "u", "filter": {"a": 1}})
        )
        .verdict,
        Allow
    );
    assert_eq!(mcp("mongodb", "find", json!({"filter": {}})).verdict, Allow);
    assert_eq!(
        mcp("filesystem", "read_file", json!({"path": "drop.sql"})).verdict,
        Allow
    );
    // A production project argument.
    assert_eq!(
        mcp(
            "neon",
            "delete_branch",
            json!({"projectId": "app-prod", "branchId": "y"})
        )
        .verdict,
        Deny
    );
}

// ---------------------------------------------------------- hook formats

fn fixture(name: &str) -> Value {
    let p = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/guard")
        .join(name);
    serde_json::from_str(&std::fs::read_to_string(&p).unwrap()).unwrap()
}

fn hook_answer(agent: Agent, input: &Value) -> (hook::HookInput, hook::Output) {
    let i = hook::parse_input(agent, input).unwrap();
    let p = Project::new();
    let l = p.loaded("");
    let d = match &i.action {
        Some(a) => evaluate(a, p.path(), &l, &|_| None),
        None => decide(Vec::new(), &GuardConfig::default(), ""),
    };
    let eff = hook::effective(agent, d.verdict, &i);
    let out = hook::render(agent, &d, eff, d.verdict);
    (i, out)
}

fn with_command(mut v: Value, path: &[&str], cmd: &str) -> Value {
    let mut cur = &mut v;
    for k in &path[..path.len() - 1] {
        cur = cur.get_mut(*k).unwrap();
    }
    cur[path[path.len() - 1]] = json!(cmd);
    v
}

#[test]
fn claude_format() {
    let base = fixture("claude_pretooluse_bash.json");
    // Allow: no output, exit 0 (Claude's own permission rules still apply).
    let (_, out) = hook_answer(Agent::Claude, &base);
    assert_eq!(
        out,
        hook::Output {
            stdout: None,
            stderr: None,
            exit: 0
        }
    );
    // Deny: JSON decision + stderr + exit 2.
    let v = with_command(
        base.clone(),
        &["tool_input", "command"],
        "npx prisma migrate reset --force",
    );
    let (_, out) = hook_answer(Agent::Claude, &v);
    assert_eq!(out.exit, 2);
    let j: Value = serde_json::from_str(out.stdout.as_deref().unwrap()).unwrap();
    assert_eq!(j["hookSpecificOutput"]["hookEventName"], "PreToolUse");
    assert_eq!(j["hookSpecificOutput"]["permissionDecision"], "deny");
    assert!(j["hookSpecificOutput"]["permissionDecisionReason"]
        .as_str()
        .unwrap()
        .contains("VG-101"));
    assert!(out.stderr.unwrap().contains("VG-101"));
    // Ask: exit 0 with "ask".
    let v = with_command(
        base.clone(),
        &["tool_input", "command"],
        "rails db:rollback",
    );
    let (_, out) = hook_answer(Agent::Claude, &v);
    assert_eq!(out.exit, 0);
    let j: Value = serde_json::from_str(out.stdout.as_deref().unwrap()).unwrap();
    assert_eq!(j["hookSpecificOutput"]["permissionDecision"], "ask");
    // Ask in bypassPermissions: nobody to ask, so deny.
    let mut v2 = v.clone();
    v2["permission_mode"] = json!("bypassPermissions");
    let (i, out) = hook_answer(Agent::Claude, &v2);
    assert!(i.unattended);
    assert_eq!(out.exit, 2);
    // MCP.
    let (i, out) = hook_answer(Agent::Claude, &fixture("claude_pretooluse_mcp.json"));
    assert!(
        matches!(i.action, Some(Action::Mcp { ref server, ref tool, .. }) if server == "supabase" && tool == "execute_sql")
    );
    #[cfg(feature = "offline")]
    assert_eq!(out.exit, 2);
    let _ = out;
    // Other tools are not checked.
    let mut other = base.clone();
    other["tool_name"] = json!("Read");
    let (i, out) = hook_answer(Agent::Claude, &other);
    assert!(i.action.is_none() && out.exit == 0 && out.stdout.is_none());
}

#[test]
fn cursor_format() {
    let base = fixture("cursor_before_shell.json");
    let (_, out) = hook_answer(Agent::Cursor, &base);
    assert_eq!(out.exit, 0);
    assert_eq!(
        serde_json::from_str::<Value>(out.stdout.as_deref().unwrap()).unwrap(),
        json!({"permission": "allow"})
    );
    let v = with_command(base.clone(), &["command"], "php artisan migrate:fresh");
    let (_, out) = hook_answer(Agent::Cursor, &v);
    let j: Value = serde_json::from_str(out.stdout.as_deref().unwrap()).unwrap();
    assert_eq!(out.exit, 0);
    assert_eq!(j["permission"], "deny");
    assert!(j["agent_message"].as_str().unwrap().contains("VG-126"));
    assert!(j["user_message"].as_str().unwrap().contains("VG-126"));
    let v = with_command(base, &["command"], "alembic downgrade -1");
    let (_, out) = hook_answer(Agent::Cursor, &v);
    let j: Value = serde_json::from_str(out.stdout.as_deref().unwrap()).unwrap();
    assert_eq!(j["permission"], "ask");
    // beforeMCPExecution: tool_input is a JSON string.
    let (i, out) = hook_answer(Agent::Cursor, &fixture("cursor_before_mcp.json"));
    assert!(matches!(i.action, Some(Action::Mcp { ref server, .. }) if server == "postgres"));
    let j: Value = serde_json::from_str(out.stdout.as_deref().unwrap()).unwrap();
    #[cfg(feature = "offline")]
    assert_eq!(j["permission"], "deny");
    let _ = j;
}

#[test]
fn codex_format() {
    let base = fixture("codex_pretooluse_bash.json");
    let (_, out) = hook_answer(Agent::Codex, &base);
    assert_eq!(
        out,
        hook::Output {
            stdout: None,
            stderr: None,
            exit: 0
        }
    );
    let v = with_command(base.clone(), &["tool_input", "command"], "rails db:drop");
    let (_, out) = hook_answer(Agent::Codex, &v);
    assert_eq!(out.exit, 2);
    assert!(out.stdout.is_none());
    assert!(out.stderr.unwrap().contains("VG-111"));
    // Codex has no ask: a medium finding is denied with a reason.
    let v = with_command(
        base.clone(),
        &["tool_input", "command"],
        "alembic downgrade -1",
    );
    let (_, out) = hook_answer(Agent::Codex, &v);
    assert_eq!(out.exit, 2);
    assert!(out.stderr.unwrap().contains("needs a human"));
    // argv-style command.
    let mut v = base;
    v["tool_input"]["command"] = json!(["bash", "-lc", "npx prisma migrate reset --force"]);
    let (_, out) = hook_answer(Agent::Codex, &v);
    assert_eq!(out.exit, 2);
}

#[test]
fn unreadable_input() {
    let (out, v) =
        hook::render_unreadable(Agent::Claude, "{not json DROP TABLE users", "invalid JSON");
    assert_eq!((v, out.exit), (Deny, 2));
    let (out, v) = hook::render_unreadable(Agent::Claude, "{garbage", "invalid JSON");
    assert_eq!((v, out.exit), (Allow, 0));
    let (out, _) = hook::render_unreadable(Agent::Cursor, "{garbage", "invalid JSON");
    assert!(out.stdout.unwrap().contains("\"allow\""));
    let (out, _) = hook::render_unreadable(Agent::Codex, "x prisma migrate reset", "invalid JSON");
    assert_eq!(out.exit, 2);
}

#[test]
fn shell_reader_does_not_panic_on_odd_input() {
    for s in [
        "",
        "\\",
        "'",
        "\"",
        "$(",
        "`",
        "<<",
        "<<<",
        "| |",
        "&& ;",
        "((",
        "))",
        "${",
        "a=",
        "=",
        "2>",
        "<(",
        ">(",
        "\u{0}",
        "é ñ 中",
        "a\\\n",
        "cat <<",
        "x <<-",
        "$'\\",
    ] {
        let _ = run(s);
    }
}

#[test]
fn deep_nesting_is_bounded() {
    let mut c = "rails db:drop".to_string();
    for _ in 0..8 {
        c = format!("bash -c {}", detect::shell_quote(&c));
    }
    // Past the depth limit the guard stops reading; it must still answer.
    let _ = run(&c);
    let mut c = "rails db:drop".to_string();
    for _ in 0..3 {
        c = format!("bash -c {}", detect::shell_quote(&c));
    }
    assert_eq!(run(&c).verdict, Deny);
}

/// Times the in-process analysis of typical commands (the hook process adds
/// its start-up; `tests/guard.rs` measures that end to end).
#[test]
fn analysis_is_fast() {
    let cmds = [
        "npm test",
        "git status",
        "ls -la src",
        "psql -c \"SELECT * FROM users WHERE id = 1\"",
        "npx prisma migrate reset --force",
        "cd api && pnpm prisma migrate dev --name add_users",
        "psql \"$DATABASE_URL\" <<'SQL'\nBEGIN;\nUPDATE accounts SET balance = 0 WHERE id = 7;\nCOMMIT;\nSQL",
        "docker compose exec -T db psql -U postgres -c 'TRUNCATE t'",
    ];
    let p = Project::new();
    let l = p.loaded("");
    let env = HashMap::new();
    // Warm the engine's rule table once, as the first call in a process does.
    let _ = run_with(&p, &l, &env, cmds[3]);
    let mut times = Vec::new();
    for _ in 0..30 {
        for c in &cmds {
            let t = std::time::Instant::now();
            let _ = run_with(&p, &l, &env, c);
            times.push(t.elapsed());
        }
    }
    times.sort();
    let p95 = times[times.len() * 95 / 100];
    eprintln!(
        "guard analysis: p50 {:?}, p95 {:?}, max {:?}",
        times[times.len() / 2],
        p95,
        times[times.len() - 1]
    );
    // Generous for debug builds on a loaded CI machine; release is ~100x under.
    assert!(p95 < std::time::Duration::from_millis(200), "p95 {p95:?}");
}
