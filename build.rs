fn main() {
    std::process::Command::new("gcc")
        .args(["test/piggie.c", "-o", "test/piggie"])
        .status()
        .unwrap();
    println!("cargo:rerun-if-changed=test/piggie.c");
}
