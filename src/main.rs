use forensic_rs::prelude::{RegistryReader, ForensicResult, RegValue};

fn main() {
    let _ = exploring_registry().unwrap();
}

fn exploring_registry() -> ForensicResult<()> {
    let mut registry  = frnsc_liveregistry_rs::LiveRegistryReader{};

    let reg_key = registry.open_key
    (forensic_rs::prelude::RegHiveKey::HkeyCurrentUser,"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ComDlg32\\LastVisitedPidlMRU")?; 
    //Abrimos la clave

    let mut reg_values = registry.enumerate_values(reg_key)?; 
    // Enumeramos todos los valores de esas claves
    
    for top in reg_values {
        println!("{top}");
        let value : Vec<u8> = registry.read_value(reg_key, &top)?.try_into()?;
        let hex = hex::encode(&value);
        println!("{:?}", hex);
    }
    return Ok(());
}

