use sentrdel_schema::schema_export::export_all;
use std::{fs, path::Path};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let output_dir = Path::new("schemas/v1");
    fs::create_dir_all(output_dir)?;

    for (name, schema) in export_all()? {
        let mut bytes = serde_json::to_vec_pretty(&schema)?;
        bytes.push(b'\n');
        fs::write(output_dir.join(name), bytes)?;
    }

    Ok(())
}
