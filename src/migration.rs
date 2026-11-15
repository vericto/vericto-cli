// SPDX-FileCopyrightText: 2026 Vericto S.A.S.
// SPDX-License-Identifier: AGPL-3.0-only

//! Which inputs of `vericto check --offline` are versioned migrations.
//!
//! The CI profile caps the engine's `SchemaMigration` rules (DROP TABLE,
//! ALTER TABLE, DROP INDEX / TRIGGER, the Snowflake and SQLite schema rules)
//! at FLAGGED because a migration legitimately drops and alters tables. Since
//! 2.3.0 the cap applies to migrations only: everything else (`--sql`, stdin,
//! any other file) is evaluated as the runtime channels evaluate it, where a
//! `DROP TABLE` is BLOCKED.
//!
//! A path is a migration when, deterministically from the path alone:
//!
//! - one of its directories is named `migrations`, `migration` or `migrate`
//!   (any case): Rails `db/migrate`, Flyway `db/migration`, Django, Prisma,
//!   Supabase, Laravel, Knex, dbmate, golang-migrate, sqlx, Diesel;
//! - its file name is a Flyway migration (`V2__add_users.sql`,
//!   `V2.1__x.sql`, `U2__undo.sql`, `B1__baseline.sql`, `R__views.sql`) or
//!   a golang-migrate one (`0001_init.up.sql`, `0001_init.down.sql`);
//! - it is, or is under, one of `.vericto.toml`'s `migration_paths`
//!   (relative to the directory `vericto` runs in, the repository root), for
//!   layouts the rules above do not know (Drizzle's `drizzle/`, sqitch's
//!   `deploy/`, a hand-rolled `sql/changes/`).
//!
//! The file's content plays no part: a `DROP TABLE` in a file is not what makes
//! the file a migration.

use std::path::Path;

/// The directory names that make a path a migration.
const MIGRATION_DIRS: &[&str] = &["migrations", "migration", "migrate"];

/// Whether `path` (as given to `check`, `-` for stdin) is a migration.
/// `extra` is `.vericto.toml`'s `migration_paths`; `cwd` is the directory
/// they are relative to (used to relate an absolute `path` to them).
pub fn is_migration(path: &str, extra: &[String], cwd: Option<&Path>) -> bool {
    if path == "-" || path.is_empty() {
        return false;
    }
    // An absolute path under the working directory is read relative to it:
    // the directories above the repository (a checkout in `/builds/migrate/`)
    // say nothing about the file, and `migration_paths` are relative to it.
    let under_cwd = Path::new(path)
        .is_absolute()
        .then(|| cwd.and_then(|c| Path::new(path).strip_prefix(c).ok()))
        .flatten();
    let parts = match under_cwd {
        Some(rest) => components(&rest.to_string_lossy()),
        None => components(path),
    };
    if let Some((name, dirs)) = parts.split_last() {
        if dirs
            .iter()
            .any(|d| MIGRATION_DIRS.iter().any(|m| d.eq_ignore_ascii_case(m)))
        {
            return true;
        }
        if is_migration_file_name(name) {
            return true;
        }
    }
    // An absolute path outside the working directory matches no
    // `migration_paths` entry.
    if Path::new(path).is_absolute() && under_cwd.is_none() {
        return false;
    }
    extra.iter().any(|prefix| {
        let prefix = components(prefix.trim());
        parts.len() >= prefix.len() && parts.iter().zip(&prefix).all(|(a, b)| a == b)
    })
}

/// The parts of a path, empty parts and `.` dropped, split on `/` and (on
/// Windows) `\`, so `db\migrate\x.sql` typed in PowerShell and a
/// `migration_paths` entry written with `/` compare alike. `..` is kept as a
/// part, so it never matches a prefix that does not spell it.
fn components(path: &str) -> Vec<String> {
    path.split(|c| c == '/' || (cfg!(windows) && c == '\\'))
        .filter(|p| !p.is_empty() && *p != ".")
        .map(str::to_string)
        .collect()
}

/// A Flyway (`V1__x.sql`, `V1.2__x.sql`, `V1_2__x.sql`, `U1__x.sql`,
/// `B1__x.sql`, `R__x.sql`) or golang-migrate (`1_x.up.sql`, `1_x.down.sql`)
/// migration file name. Flyway's prefixes are case-sensitive; the `.sql`
/// extension is not.
fn is_migration_file_name(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    let Some(stem) = lower.strip_suffix(".sql").map(|s| &name[..s.len()]) else {
        return false;
    };
    let stem_lower = stem.to_ascii_lowercase();
    if stem_lower.ends_with(".up") || stem_lower.ends_with(".down") {
        return stem.starts_with(|c: char| c.is_ascii_digit());
    }
    if let Some(desc) = stem.strip_prefix("R__") {
        return !desc.is_empty();
    }
    let Some(rest) = stem.strip_prefix(['V', 'U', 'B']) else {
        return false;
    };
    let Some((version, desc)) = rest.split_once("__") else {
        return false;
    };
    !desc.is_empty()
        && version.starts_with(|c: char| c.is_ascii_digit())
        && version
            .chars()
            .all(|c| c.is_ascii_digit() || c == '.' || c == '_')
}

#[cfg(test)]
mod tests {
    use super::*;

    fn m(path: &str) -> bool {
        is_migration(path, &[], None)
    }

    #[test]
    fn migration_directories() {
        for p in [
            "db/migrate/20260101000000_drop_legacy.sql",
            "db/migration/V1__init.sql",
            "migrations/0001_init.sql",
            "./supabase/migrations/20260101_x.sql",
            "prisma/migrations/20260101_init/migration.sql",
            "database/Migrations/x.sql",
            "app/MIGRATE/x.sql",
        ] {
            assert!(m(p), "{p}");
        }
        for p in [
            "schema.sql",
            "db/schema.sql",
            "db/seeds.sql",
            "migrations.sql",
            "sql/migrations_old.sql",
            "queries/drop_users.sql",
            "-",
            "",
        ] {
            assert!(!m(p), "{p}");
        }
    }

    #[test]
    fn migration_file_names() {
        for p in [
            "sql/V1__init.sql",
            "sql/V2.1__add_users.sql",
            "sql/V2_1__add_users.SQL",
            "sql/U2__undo.sql",
            "sql/B1__baseline.sql",
            "sql/R__views.sql",
            "sql/0001_init.up.sql",
            "sql/0001_init.down.sql",
        ] {
            assert!(m(p), "{p}");
        }
        for p in [
            "sql/v1__init.sql",
            "sql/V__init.sql",
            "sql/V1__.sql",
            "sql/R__.sql",
            "sql/Vacuum__x.sql",
            "sql/V1_init.sql",
            "sql/V1__init.txt",
            "sql/setup.up.sql",
            "sql/backup.sql",
        ] {
            assert!(!m(p), "{p}");
        }
    }

    #[test]
    fn configured_migration_paths() {
        let extra = vec!["drizzle".to_string(), "sql/changes/".to_string()];
        let cwd = Path::new("/repo");
        assert!(is_migration("drizzle/0000_init.sql", &extra, Some(cwd)));
        assert!(is_migration("./drizzle/meta/x.sql", &extra, Some(cwd)));
        assert!(is_migration("sql/changes/2026/x.sql", &extra, Some(cwd)));
        // Absolute paths: `/repo` is not absolute on Windows (no drive).
        if cfg!(unix) {
            assert!(is_migration(
                "/repo/drizzle/0000_init.sql",
                &extra,
                Some(cwd)
            ));
            assert!(!is_migration("/elsewhere/drizzle/x.sql", &extra, Some(cwd)));
        }
        assert!(!is_migration("drizzle-old/x.sql", &extra, Some(cwd)));
        assert!(!is_migration("sql/x.sql", &extra, Some(cwd)));
        assert!(!is_migration("src/drizzle/x.sql", &extra, Some(cwd)));
        assert!(!is_migration("../drizzle/x.sql", &extra, Some(cwd)));
        // Directories above the working directory do not count.
        if cfg!(unix) {
            assert!(!is_migration(
                "/builds/migrate/repo/schema.sql",
                &[],
                Some(Path::new("/builds/migrate/repo"))
            ));
            assert!(is_migration(
                "/builds/repo/db/migrate/x.sql",
                &[],
                Some(Path::new("/builds/repo"))
            ));
        }
        assert!(!is_migration("-", &extra, Some(cwd)));
        // `.` lists every file of the repository: a visible, reviewed choice.
        assert!(is_migration("any/x.sql", &[".".to_string()], Some(cwd)));
    }
}
