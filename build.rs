extern crate protobuf_codegen_pure;

fn main() {
    protobuf_codegen_pure::Codegen::new()
        .out_dir("src/proto")
        .inputs(&["proto/rpc.proto"])
        .include("proto")
        .run()
        .expect("Codegen failed.");

    std::process::Command::new("gcc")
        .args(&["test/piggie.c", "-o", "test/piggie"])
        .status()
        .unwrap();
}
