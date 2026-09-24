use assert_cmd::Command;
use predicates::str::contains;

fn sparrow() -> Command {
    Command::cargo_bin("sparrow").unwrap()
}

#[test]
fn prints_version() {
    sparrow()
        .arg("--version")
        .assert()
        .success()
        .stdout(contains("sparrow 0.1.0"));
}
