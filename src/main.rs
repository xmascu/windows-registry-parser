#![allow(non_snake_case)]

use forensic_rs::prelude::{ForensicResult, RegistryReader};
use std::fmt::Write;
use std::{ops::Add, u8};

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
        if top.eq("MRUListEx") {
        } else {
            println!("----------- {}", top);

            let reg_vec_decimal: Vec<u8> = registry.read_value(reg_key, &top)?.try_into()?;

            let len_program = get_length_slice(&reg_vec_decimal[..]).unwrap();

            let program_name = get_program_name(&reg_vec_decimal[..len_program]);
            println!("El programa utilizado es: {}", program_name);

            let reg_hex = slice_to_hex(&reg_vec_decimal[len_program.add(2)..]);
            get_shellbags_info(reg_hex);
        }
    }
    return Ok(());
}

fn get_shellbags_info(data: String) {
    let mut result = Vec::new();

    let array_shellbags = 
    [
        "00:??","01:??","17:??","1e:??","1f:Root Folder Shell Item","20:Volume Shell Item","21:Volume Shell Item","22:Volume Shell Item","23:Volume Shell Item",
        "24:Volume Shell Item","25:Volume Shell Item","26:Volume Shell Item","27:Volume Shell Item","28:Volume Shell Item","29:Volume Shell Item","2a:Volume Shell Item",
        "2b:Volume Shell Item","2c:Volume Shell Item","2d:Volume Shell Item","2e:Volume Shell Item","2f:Volume Shell Item","30:File Entry Shell Item","31:File Entry Shell Item",
        "32:File Entry Shell Item","33:File Entry Shell Item","34:File Entry Shell Item","35:File Entry Shell Item","36:File Entry Shell Item","37:File Entry Shell Item",
        "38:File Entry Shell Item","39:File Entry Shell Item","3a:File Entry Shell Item","3b:File Entry Shell Item","3c:File Entry Shell Item","3d:File Entry Shell Item",
        "3e:File Entry Shell Item","3f:File Entry Shell Item","40:Network Location Shell Item","41:Network Location Shell Item","42:Network Location Shell Item",
        "43:Network Location Shell Item","44:Network Location Shell Item","45:Network Location Shell Item","46:Network Location Shell Item","47:Network Location Shell Item",
        "48:Network Location Shell Item","49:Network Location Shell Item","4a:Network Location Shell Item","4b:Network Location Shell Item","4c:Network Location Shell Item",
        "4d:Network Location Shell Item","4e:Network Location Shell Item","4f:Network Location Shell Item","52:Compressed Folder Shell Item","61:URI Shell Item","71:Control Panel"
    ];


    for (i, c) in data.chars().enumerate() {
        if i % 2 == 0 {
            result.push(c.to_string());
        } else {
            let len = result.len();
            result[len - 1] += &c.to_string();
        }
    }

    let len_shellbags = u32::from_str_radix(&&result[0], 16).unwrap();
    println!("La longitud de la ShellBag es de: {} bytes", len_shellbags);

    let type_shellbags = &result[2];

    for shellbag in array_shellbags.iter() {
        let parts: Vec<&str> = shellbag.split(':').collect();

        if parts[0].eq(type_shellbags) { //SI ES UNA 1F=Root Folder Shell IteM
            println!("El tipo de ShellBag es: {}", parts[1]);
            get_shell_folder(result.to_vec());
        }
    }

    
    
}

fn get_shell_folder(result: Vec<String>) {
    let array_systemfolders = 
    [
        "00:Explorer","42:Libraries","44:Users","4c:Public","50:My Computer","58:My Network Places","60:Recycle Bin","68:Explorer","70:Control Panel","78:Recycle Bin","80:My Games",
    ];

    let array_folders = 
    [
        "724ef170-a42d-4fef-9f26-b60e846fba4f:Administrative Tools", "d0384e7d-bac3-4797-8f14-cba229b392b5:Common Administrative Tools", 
        "de974d24-d9c6-4d3e-bf91-f4455120b917:Common Files", "c1bae2d0-10df-4334-bedd-7aa20b227a9d:Common OEM Links", "5399e694-6ce5-4d6c-8fce-1d8870fdcba0:Control Panel", 
        "1ac14e77-02e7-4e5d-b744-2eb1ae5198b7:CSIDL_SYSTEM","b4bfcc3a-db2c-424c-b029-7fe99a87c641:Desktop","7b0db17d-9cd2-4a93-9733-46cc89022e7c:Documents Library",
        "fdd39ad0-238f-46af-adb4-6c85480369c7:Documents","374de290-123f-4565-9164-39c4925e467b:Downloads","de61d971-5ebc-4f02-a3a9-6c82895e5c04:Get Programs",
        "a305ce99-f527-492b-8b1a-7e76fa98d6e4:Installed Updates","871c5380-42a0-1069-a2ea-08002b30309d:Internet Explorer","031e4825-7b94-4dc3-b131-e946b44c8dd5:Libraries",
        "4bd8d571-6d19-48d3-be97-422220080e43:Music","20d04fe0-3aea-1069-a2d8-08002b30309d:My Computer","450d8fba-ad25-11d0-98a8-0800361b1103:My Documents",
        "ed228fdf-9ea8-4870-83b1-96b02cfe0d52:My Games","208d2c60-3aea-1069-a2d7-08002b30309d:My Network Places","f02c1a0d-be21-4350-88b0-7367fc96ef3c:Network",
        "33e28130-4e1e-4676-835a-98395c3bc3bb:Pictures","a990ae9f-a03b-4e80-94bc-9912d7504104:Pictures","7c5a40ef-a0fb-4bfc-874a-c0f2e0b9fa8e:Program Files (x86)",
        "905e63b6-c1bf-494e-b29c-65b732d3d21a:Program Files","df7266ac-9274-4867-8d55-3bd661de872d:Programs and Features","3214fab5-9757-4298-bb61-92a9deaa44ff:Public Music",
        "b6ebfb86-6907-413c-9af7-4fc2abf07cc5:Public Pictures","2400183a-6185-49fb-a2d8-4a392a602ba3:Public Videos","4336a54d-38b-4685-ab02-99bb52d3fb8b:Public",
        "491e922f-5643-4af4-a7eb-4e7a138d8174:Public","dfdf76a2-c82a-4d63-906a-5644ac457385:Public","645ff040-5081-101b-9f08-00aa002f954e:Recycle Bin",
        "d65231b0-b2f1-4857-a4ce-a8e7c6ea7d27:System32 (x86)","9e52ab10-f80d-49df-acb8-4330f5687855:Temporary Burn Folder","f3ce0f7c-4901-4acc-8648-d5d44b04ef8f:Users Files",
        "59031a47-3f72-44a7-89c5-5595fe6b30ee:Users","f38bf404-1d43-42f2-9305-67de0b28fc23:Windows"
    ];

    let type_systemfolder = &result[3];

    for folder in array_systemfolders.iter() {
        let parts: Vec<&str> = folder.split(':').collect();

        if parts[0].eq(type_systemfolder) {
            println!("El tipo de System Folder es: {}", parts[1]);
        }
    }

    let mut shell_folder_id1 = result[4..8].to_vec();
    shell_folder_id1.reverse();

    let mut shell_folder_id2 = result[8..10].to_vec();
    shell_folder_id2.reverse();

    let mut shell_folder_id3 = result[10..12].to_vec();
    shell_folder_id3.reverse();

    let mut shell_folder_id4 = result[12..14].to_vec();
    shell_folder_id4.reverse();

    let shell_folder_id5 = result[14..20].to_vec();

    let shell_folder_concat = vec![shell_folder_id1,shell_folder_id2,shell_folder_id3,shell_folder_id4,shell_folder_id5];

    let shell_folder: String = shell_folder_concat
                                    .into_iter()
                                    .map(|vec| vec.join(""))
                                    .collect::<Vec<String>>()
                                    .join("-");

    for folder in array_folders.iter() {
        let parts: Vec<&str> = folder.split(':').collect();

        if parts[0].eq(&shell_folder) {
            println!("El tipo de Folder es: {}", parts[1]);
        }
    }
}

fn slice_to_hex(slice: &[u8]) -> String {
    let mut hex = String::new();
    for byte in slice {
        write!(&mut hex, "{:02x}", byte).unwrap();
    }
    hex
}

// Obtenemos el tamaño de una slice entera, es decir, desde un 0000 al siguiente
fn get_length_slice(value: &[u8]) -> Option<usize> {
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
