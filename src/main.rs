use std::{u8,str};
use forensic_rs::prelude::{RegistryReader, ForensicResult};

fn main() {
    let _ = last_visited_pid_mru().unwrap();
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
            let mut reg_vec_decimal : Vec<u8> = registry.read_value(reg_key, &top)?.try_into()?;
            let reg_hex = vec_u8_to_vec_hex(reg_vec_decimal);

            let mut contador = 0;
            let mut aux = String::new().to_owned();
            let mut hex_split: Vec<String> = Vec::new();

            for i in reg_hex {
                
                if i.eq("00") {
                    contador = contador + 1;
                }
                else {
                    contador = 0;
                    aux.push_str(&i);
                }

                if contador == 3 {
                    hex_split.push(aux.to_owned());
                    aux.clear();
                }
            }

            // NOMBRE DEL PROGRAMA UTILIZADO
            let program_name = parse_hex_string_to_ascii_string(&hex_split[0]);
            println!("{:?}", program_name);
            println!("{:?}", hex_split);
            
            
        }
    }
    return Ok(());
}

fn vec_u8_to_vec_hex(value : Vec<u8>) -> Vec<String> {

    let mut vec : Vec<String> = Vec::new();

    for i in value {
        let hex = format!("{:02X}", i);
        vec.push(hex);
    }

    return vec;
}

fn parse_hex_string_to_ascii_string (hex_string : &String) -> String {

    let subs = hex_string.as_bytes()
                        .chunks(2)
                        .map(str::from_utf8)
                        .collect::<Result<Vec<&str>, _>>()
                        .unwrap();

    let mut aux = String::new().to_owned();

    for y in subs {
        let char = u8::from_str_radix(y, 16).map(|n| n as char).unwrap();
        aux.push(char);
    }

    return aux;

}

