use forensic_rs::prelude::{RegistryReader, ForensicResult};

fn main() {
    let _ = last_visited_pid_mru().unwrap();
    println!("--------------CAMBIO DE REGISTRO----------------------");
    let _ = open_save_pid_mru().unwrap();
}

fn last_visited_pid_mru() -> ForensicResult<()> {
    let mut registry  = frnsc_liveregistry_rs::LiveRegistryReader{};

    let reg_key = registry.open_key
    (forensic_rs::prelude::RegHiveKey::HkeyCurrentUser,"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ComDlg32\\LastVisitedPidlMRU")?; 
    //Abrimos la clave

    let reg_values = registry.enumerate_values(reg_key)?; 
    // Enumeramos todos los valores
    
    for top in reg_values {
        println!("------------ {}", top);
        if !top.eq("MRUListEx") {
            let value : Vec<u8> = registry.read_value(reg_key, &top)?.try_into()?;
            let vec = vec_u8_to_vec_char(value);
            let strin: String = vec.iter().collect::<String>();
            let split: Vec<String> = strin.split("PO :i+00").map(str::to_string).collect();
            println!("Program used to open / save as: {:?}", &split[0]);
            println!("Directory where the file was: {:?}", &split[1]);
        }
    }
    return Ok(());
}

fn open_save_pid_mru() -> ForensicResult<()> {
    let mut registry  = frnsc_liveregistry_rs::LiveRegistryReader{};

    let reg_key = registry.open_key
    (forensic_rs::prelude::RegHiveKey::HkeyCurrentUser,"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ComDlg32\\OpenSavePidlMRU\\*")?; 
    //Abrimos la clave

    let reg_values = registry.enumerate_values(reg_key)?; 
    // Enumeramos todos los valores
    
    for top in reg_values {
        println!("------------ {}", top);
        let value : Vec<u8> = registry.read_value(reg_key, &top)?.try_into()?;
        let vec = vec_u8_to_vec_char(value);
        let strin: String = vec.iter().collect::<String>();
        println!("{}", strin);
    }
    return Ok(());
}

fn vec_u8_to_vec_char(value : Vec<u8>) -> Vec<char> {

    let mut vec : Vec<char> = Vec::new();

    for i in value {
        if i >= 32 && i <= 126 {
            vec.push(i as char);
        }    
    }

    return vec;
}

