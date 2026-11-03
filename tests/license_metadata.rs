// SPDX-FileCopyrightText: 2026 Vericto S.A.S.
// SPDX-License-Identifier: AGPL-3.0-only

//! Release-law metadata must change together instead of creating two licenses
//! for one version, a binary that embeds an engine under another license, or a
//! release whose pinned versions disagree with its manifest.

use std::fs;

/// A repository file as text, with line endings normalised to `\n`. Git checks
/// text files out with CRLF on Windows (`core.autocrlf`), and the checks below
/// match multi-line passages, so they must not depend on the checkout.
fn root(path: &str) -> String {
    fs::read_to_string(format!("{}/{}", env!("CARGO_MANIFEST_DIR"), path))
        .unwrap_or_else(|error| panic!("cannot read {path}: {error}"))
        .replace("\r\n", "\n")
}

/// The `version` of the `[[package]]` named `name` in Cargo.lock, with its source.
fn locked(name: &str) -> (String, Option<String>) {
    let lock = root("Cargo.lock");
    let mut lines = lock.lines();
    while let Some(line) = lines.next() {
        if line == format!("name = \"{name}\"") {
            let version = lines
                .next()
                .and_then(|l| l.strip_prefix("version = \""))
                .and_then(|l| l.strip_suffix('"'))
                .unwrap_or_else(|| panic!("no version after {name} in Cargo.lock"))
                .to_string();
            let source = lines
                .next()
                .and_then(|l| l.strip_prefix("source = \""))
                .and_then(|l| l.strip_suffix('"'))
                .map(str::to_string);
            return (version, source);
        }
    }
    panic!("{name} is not in Cargo.lock");
}

#[test]
fn version_2_is_the_first_agpl_release_everywhere() {
    let version = env!("CARGO_PKG_VERSION");
    let major: u64 = version.split('.').next().unwrap().parse().unwrap();
    assert!(
        major >= 2,
        "AGPL metadata must not be published as version 1.13.3 or earlier"
    );

    let manifest = root("Cargo.toml");
    assert!(manifest.contains("license = \"AGPL-3.0-only\""));

    let history = root("LICENSE_HISTORY.md");
    assert!(history.contains("tag `v2.0.0`"));
    // The last FSL release and the start of the FSL period.
    assert!(history.contains("ff8f1b8cbfb28ee2b6ed8015c29e7518b8fb9058"));
    assert!(history.contains("530a641b82a9bde22861dcf75c8f057c27fb7c65"));
    // The last Elastic release is never reported as FSL or AGPL.
    assert!(history.contains("`v1.9.0`"));
}

#[test]
fn the_release_version_is_pinned_consistently() {
    let version = env!("CARGO_PKG_VERSION");
    let (cli, cli_source) = locked("vericto-cli");
    assert_eq!(
        cli, version,
        "Cargo.lock is stale: run `cargo update -p vericto-cli`"
    );
    assert!(cli_source.is_none(), "vericto-cli is the workspace root");

    let hooks = root(".pre-commit-hooks.yaml");
    assert_eq!(
        hooks
            .matches(&format!("@vericto/vericto-cli@{version}"))
            .count(),
        2,
        ".pre-commit-hooks.yaml must pin the release in both hooks"
    );

    let readme = root("README.md");
    assert!(readme.contains(&format!("$v = \"{version}\"")));
    assert!(readme.contains(&format!("rev: v{version} ")));
}

#[test]
fn the_embedded_engine_is_the_agpl_release_the_manifest_names() {
    let manifest = root("Cargo.toml");
    let tag = manifest
        .lines()
        .find(|l| l.starts_with("vericto-engine = "))
        .and_then(|l| l.split("tag = \"").nth(1))
        .and_then(|l| l.split('"').next())
        .expect("vericto-engine must be pinned by tag in Cargo.toml");

    let (engine, source) = locked("vericto-engine");
    let major: u64 = engine.split('.').next().unwrap().parse().unwrap();
    assert!(
        major >= 5,
        "engine {engine} is under FSL-1.1-ALv2 or an earlier license, not AGPL-3.0-only"
    );
    assert_eq!(tag, format!("v{engine}"));
    let source = source.expect("vericto-engine is a git dependency");
    assert!(source.contains(&format!("?tag={tag}#")), "{source}");

    let deny = root("deny.toml");
    assert!(deny.contains("{ allow = [\"AGPL-3.0-only\"], crate = \"vericto-cli\" }"));
    assert!(deny.contains("{ allow = [\"AGPL-3.0-only\"], crate = \"vericto-engine\" }"));
    assert!(!deny.contains("FSL-1.1-ALv2\"], crate"));

    let notices = root("THIRD_PARTY_LICENSES");
    assert!(notices.contains(&format!("vericto-engine {engine}: AGPL-3.0-only")));
}

#[test]
fn public_license_is_the_unmodified_agpl() {
    let license = root("LICENSE");
    assert!(license.starts_with("                    GNU AFFERO GENERAL PUBLIC LICENSE\n"));
    assert!(license.contains("Version 3, 19 November 2007"));
    assert!(license.contains("Everyone is permitted to copy and distribute verbatim copies\n"));
    assert!(license.contains("of this license document, but changing it is not allowed."));
}

#[test]
fn cla_workflow_uses_the_permanent_v1_1_document_and_record() {
    let index = root("CLA.md");
    assert!(index.contains("[ICLA version 1.1](legal/cla/1.1.md)"));
    assert!(root("legal/cla/1.1.md").contains("Version 1.1"));
    assert!(root("legal/cla/1.0.md").contains("Version 1.0"));

    let workflow = root(".github/workflows/cla.yml");
    assert!(workflow.contains("const claPath = \"legal/cla/1.1.md\";"));
    assert!(workflow.contains("signatures/v1.1/cla.json"));
    assert!(workflow.contains("const exemptAccounts = new Set([\"vericto\", \"donkan168\"]);"));
    assert!(workflow.contains(
        "const allowedBots = new Set([\"vericto-bot[bot]\", \"dependabot[bot]\", \"github-actions[bot]\"]);"
    ));
    assert!(workflow.contains("} else if (!exemptAccounts.has(author.login)) {"));
    assert!(workflow.contains("context.payload.comment.body === signatureSentence"));
    assert!(!workflow.contains("contains(github.event.comment.body"));
    assert!(workflow.contains("github.paginate(github.rest.pulls.listCommits"));
    assert!(workflow.contains("github.paginate(github.rest.issues.listComments"));
    assert!(workflow.contains("Co-authored-by:"));
    assert!(workflow.contains("commit.commit.verification?.verified !== true"));
    assert!(workflow.contains("cla_document_sha256: claDocumentSha256"));
    assert!(workflow.contains("entry.cla_version === claVersion"));
    assert!(workflow.contains("All contributors have signed the CLA ✍️ ✅"));
    assert!(!workflow.contains("contributor-assistant/github-action"));
}

#[test]
fn image_and_installer_metadata_use_the_same_license() {
    let docker = root(".github/workflows/docker.yml");
    assert!(docker.contains("org.opencontainers.image.licenses=AGPL-3.0-only"));
    assert!(
        root("Dockerfile").contains("LABEL org.opencontainers.image.licenses=\"AGPL-3.0-only\"")
    );

    // The licenses and notices ship in every archive, next to the binary.
    let dist = root("dist-workspace.toml");
    assert!(dist.contains("include = [\"NOTICE\", \"THIRD_PARTY_LICENSES\"]"));

    let notice = root("NOTICE");
    assert!(notice.contains("Version 2.0.0 of the CLI pins version 5.0.0 of the\nengine"));

    assert!(root("windows/package.js").contains("const LICENSE = \"AGPL-3.0-only\";"));
    for manifest in [
        "package.json",
        "npm-installer/package.json",
        "windows/package.json",
    ] {
        assert!(
            root(manifest).contains("\"license\": \"AGPL-3.0-only\""),
            "{manifest}"
        );
    }
}
