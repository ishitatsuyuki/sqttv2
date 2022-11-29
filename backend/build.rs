fn main() -> Result<(), Box<dyn std::error::Error>> {
    tonic_build::compile_protos("../proto/sqtt/v2/sqtt.proto")?;
    Ok(())
}
