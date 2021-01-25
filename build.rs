fn main() {
    tonic_build::compile_protos("proto/mediator.proto").unwrap();
}
