#![allow(non_snake_case)]

use forensic_rs::prelude::{ForensicResult, RegistryReader};
use std::u8;

fn main() {
    let _ = last_visited_pid_mru().unwrap();
}

fn last_visited_pid_mru() -> ForensicResult<()> {
    let mut registry = frnsc_liveregistry_rs::LiveRegistryReader {};

    let reg_key = registry.open_key(
        forensic_rs::prelude::RegHiveKey::HkeyCurrentUser,
        "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ComDlg32\\LastVisitedPidlMRU",
    )?;
    //Abrimos la clave

    let reg_values = registry.enumerate_values(reg_key)?;
    // Enumeramos todos los valores

    for top in reg_values {
        if top.eq("MRUListEx") { } 
        else {
            println!("----------- {}", top);

            let reg_vec_decimal: Vec<u8> = registry.read_value(reg_key, &top)?.try_into()?;
            println!("{:?}", reg_vec_decimal);

            let len_program = len_slice(&reg_vec_decimal[..]);


            let program_name = get_program_name(&reg_vec_decimal[..len_program.unwrap()]);

            println!("{}", program_name);
        }
    }
    return Ok(());
}

fn len_slice(value: &[u8]) -> Option<usize> {
    let max_length = value.len() - (value.len() % 2);

    for pos in (0..max_length).step_by(2) {
        if value[pos] == 0 && value[pos + 1] == 0 {
            return Some(pos);
        }
    }
    None
}

fn get_program_name(value: &[u8]) -> String {
    let mut unicode_string = String::new();

    for u8_value in value.iter() {
        let unicode_char: char = *u8_value as char;
        unicode_string.push(unicode_char);
    }

    return unicode_string;
}
