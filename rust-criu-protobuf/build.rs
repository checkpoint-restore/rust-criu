extern crate protobuf_codegen;

fn main() {
    protobuf_codegen::Codegen::new()
        .includes(["proto"])
        .input("proto/rpc.proto")
        .out_dir("src")
        .run_from_script();

    println!("cargo:rerun-if-changed=proto/rpc.proto");
}
