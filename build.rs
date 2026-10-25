fn main() {
    if std::env::var_os("GENERATE_PROTOBUF").is_some() {
        #[cfg(feature = "protobuf-codegen")]
        protobuf_codegen::Codegen::new()
            .includes(["proto"])
            .input("proto/rpc.proto")
            .out_dir("src/rust_criu_protobuf")
            .run_from_script();
        #[cfg(not(feature = "protobuf-codegen"))]
        panic!("GENERATE_PROTOBUF requires the protobuf-codegen feature");
    }

    if std::env::var_os("GENERATE_TEST_PROCESS").is_some() {
        std::process::Command::new("gcc")
            .args(["test/piggie.c", "-o", "test/piggie"])
            .status()
            .unwrap();
        std::process::Command::new("gcc")
            .args(["test/loop.c", "-o", "test/loop"])
            .status()
            .unwrap();
        std::process::Command::new("gcc")
            .args(["test/loop_pts.c", "-o", "test/loop_pts"])
            .status()
            .unwrap();
    }
    println!("cargo:rerun-if-changed=test/piggie.c");
    println!("cargo:rerun-if-changed=test/loop.c");
    println!("cargo:rerun-if-changed=test/loop_pts.c");
    println!("cargo:rerun-if-changed=proto/rpc.proto");
    println!("cargo:rerun-if-env-changed=GENERATE_PROTOBUF");
    println!("cargo:rerun-if-env-changed=GENERATE_TEST_PROCESS");
}
