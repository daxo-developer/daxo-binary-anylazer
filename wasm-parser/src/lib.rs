use wasm_bindgen::prelude::*;
use serde::{Serialize, Deserialize};

// Используем wee_alloc как глобальный аллокатор для уменьшения размера WASM
#[global_allocator]
static ALLOC: wee_alloc::WeeAlloc = wee_alloc::WeeAlloc::INIT;

// -----------------------------------------------------------------------------
// Структуры для сериализации в JSON
// -----------------------------------------------------------------------------

#[derive(Debug, Serialize, Deserialize)]
struct BinaryInfo {
    file_type: String,
    size: usize,
    wasm: Option<WasmInfo>,
    elf: Option<ElfInfo>,
}

#[derive(Debug, Serialize, Deserialize)]
struct WasmInfo {
    magic: String,
    version: u32,
    sections: Vec<WasmSection>,
}

#[derive(Debug, Serialize, Deserialize)]
struct WasmSection {
    id: u8,
    name: String,
    size: usize,
    // дополнительные поля для некоторых секций
    details: Option<serde_json::Value>,
}

#[derive(Debug, Serialize, Deserialize)]
struct ElfInfo {
    class: String,
    endianness: String,
    version: u32,
    os_abi: String,
    abi_version: u8,
    entry_point: u64,
    program_header_offset: u64,
    section_header_offset: u64,
    flags: u32,
    header_size: u16,
    program_header_entry_size: u16,
    program_header_count: u16,
    section_header_entry_size: u16,
    section_header_count: u16,
    section_header_string_index: u16,
    sections: Vec<ElfSection>,
    segments: Vec<ElfSegment>,
}

#[derive(Debug, Serialize, Deserialize)]
struct ElfSection {
    name: String,
    typ: u32,
    flags: u64,
    addr: u64,
    offset: u64,
    size: u64,
    link: u32,
    info: u32,
    align: u64,
    entry_size: u64,
}

#[derive(Debug, Serialize, Deserialize)]
struct ElfSegment {
    typ: u32,
    flags: u32,
    offset: u64,
    vaddr: u64,
    paddr: u64,
    filesz: u64,
    memsz: u64,
    align: u64,
}

// -----------------------------------------------------------------------------
// Основная экспортируемая функция
// -----------------------------------------------------------------------------

#[wasm_bindgen]
pub fn parse_binary(data: &[u8]) -> String {
    if data.len() < 4 {
        return json_error("File too small");
    }

    // Определяем тип по магическим байтам
    let magic = &data[0..4];
    let result = if magic == b"\x00asm" {
        parse_wasm(data)
    } else if magic[0] == 0x7F && &data[1..4] == b"ELF" {
        parse_elf(data)
    } else {
        return json_error("Unsupported file format (only WASM and ELF)");
    };

    match result {
        Ok(info) => serde_json::to_string(&info).unwrap_or_else(|_| json_error("Serialization error")),
        Err(e) => json_error(&e),
    }
}

fn json_error(msg: &str) -> String {
    serde_json::json!({ "error": msg }).to_string()
}

// =============================================================================
// Парсер WASM
// =============================================================================

fn parse_wasm(data: &[u8]) -> Result<BinaryInfo, String> {
    let mut offset = 8; // после магии и версии
    let version = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);

    let mut sections = Vec::new();
    while offset < data.len() {
        if offset + 1 > data.len() {
            break;
        }
        let id = data[offset];
        offset += 1;
        let (size, bytes_read) = read_leb128_u64(&data[offset..])?;
        offset += bytes_read;
        let section_end = offset + size as usize;
        if section_end > data.len() {
            break;
        }

        let name = match id {
            0 => "Custom",
            1 => "Type",
            2 => "Import",
            3 => "Function",
            4 => "Table",
            5 => "Memory",
            6 => "Global",
            7 => "Export",
            8 => "Start",
            9 => "Element",
            10 => "Code",
            11 => "Data",
            _ => "Unknown",
        };

        // Попробуем извлечь дополнительные данные для некоторых секций
        let details = match id {
            1 => parse_type_section(&data[offset..section_end]),
            2 => parse_import_section(&data[offset..section_end]),
            7 => parse_export_section(&data[offset..section_end]),
            _ => None,
        };

        sections.push(WasmSection {
            id,
            name: name.to_string(),
            size: size as usize,
            details,
        });

        offset = section_end;
    }

    Ok(BinaryInfo {
        file_type: "WASM".to_string(),
        size: data.len(),
        wasm: Some(WasmInfo {
            magic: format!("{:02x?}", &data[0..4]),
            version,
            sections,
        }),
        elf: None,
    })
}

// Вспомогательные функции для чтения LEB128
fn read_leb128_u64(data: &[u8]) -> Result<(u64, usize), String> {
    let mut result = 0u64;
    let mut shift = 0;
    let mut bytes_read = 0;
    for &byte in data.iter() {
        bytes_read += 1;
        result |= ((byte & 0x7F) as u64) << shift;
        if byte & 0x80 == 0 {
            return Ok((result, bytes_read));
        }
        shift += 7;
        if shift >= 64 {
            return Err("LEB128 overflow".to_string());
        }
    }
    Err("Incomplete LEB128".to_string())
}

// Парсинг секции Type (только количество)
fn parse_type_section(data: &[u8]) -> Option<serde_json::Value> {
    if data.is_empty() { return None; }
    let (count, _) = read_leb128_u64(data).ok()?;
    Some(serde_json::json!({ "function_count": count }))
}

// Парсинг секции Import (список импортов)
fn parse_import_section(data: &[u8]) -> Option<serde_json::Value> {
    if data.is_empty() { return None; }
    let (count, mut off) = read_leb128_u64(data).ok()?;
    let mut imports = Vec::new();
    for _ in 0..count {
        // читаем module name
        let (mod_len, read) = read_leb128_u64(&data[off..]).ok()?;
        off += read;
        let module = String::from_utf8_lossy(&data[off..off + mod_len as usize]).to_string();
        off += mod_len as usize;

        let (name_len, read) = read_leb128_u64(&data[off..]).ok()?;
        off += read;
        let name = String::from_utf8_lossy(&data[off..off + name_len as usize]).to_string();
        off += name_len as usize;

        let kind = data[off];
        off += 1;
        // пропускаем детали типа (в зависимости от kind)
        match kind {
            0x00 => { // Function
                let (idx, read) = read_leb128_u64(&data[off..]).ok()?;
                off += read;
                imports.push(serde_json::json!({
                    "module": module,
                    "name": name,
                    "kind": "function",
                    "type_index": idx
                }));
            }
            0x01 => { // Table
                let elem_type = data[off];
                off += 1;
                let (flags, read) = read_leb128_u64(&data[off..]).ok()?;
                off += read;
                let (initial, read) = read_leb128_u64(&data[off..]).ok()?;
                off += read;
                let max = if flags & 1 != 0 {
                    let (m, read) = read_leb128_u64(&data[off..]).ok()?;
                    off += read;
                    Some(m)
                } else { None };
                imports.push(serde_json::json!({
                    "module": module,
                    "name": name,
                    "kind": "table",
                    "elem_type": elem_type,
                    "initial": initial,
                    "max": max
                }));
            }
            0x02 => { // Memory
                let (flags, read) = read_leb128_u64(&data[off..]).ok()?;
                off += read;
                let (initial, read) = read_leb128_u64(&data[off..]).ok()?;
                off += read;
                let max = if flags & 1 != 0 {
                    let (m, read) = read_leb128_u64(&data[off..]).ok()?;
                    off += read;
                    Some(m)
                } else { None };
                imports.push(serde_json::json!({
                    "module": module,
                    "name": name,
                    "kind": "memory",
                    "initial_pages": initial,
                    "max_pages": max
                }));
            }
            0x03 => { // Global
                let val_type = data[off];
                off += 1;
                let mutability = data[off];
                off += 1;
                // пропускаем инициализирующее выражение (упрощённо)
                // в реальности нужно разобрать, но для демонстрации пропускаем
                while data[off] != 0x0B { off += 1; }
                off += 1; // skip end
                imports.push(serde_json::json!({
                    "module": module,
                    "name": name,
                    "kind": "global",
                    "type": val_type,
                    "mutability": mutability
                }));
            }
            _ => {}
        }
    }
    Some(serde_json::json!({ "imports": imports }))
}

// Парсинг секции Export
fn parse_export_section(data: &[u8]) -> Option<serde_json::Value> {
    if data.is_empty() { return None; }
    let (count, mut off) = read_leb128_u64(data).ok()?;
    let mut exports = Vec::new();
    for _ in 0..count {
        let (name_len, read) = read_leb128_u64(&data[off..]).ok()?;
        off += read;
        let name = String::from_utf8_lossy(&data[off..off + name_len as usize]).to_string();
        off += name_len as usize;
        let kind = data[off];
        off += 1;
        let (idx, read) = read_leb128_u64(&data[off..]).ok()?;
        off += read;
        let kind_str = match kind {
            0x00 => "function",
            0x01 => "table",
            0x02 => "memory",
            0x03 => "global",
            _ => "unknown",
        };
        exports.push(serde_json::json!({
            "name": name,
            "kind": kind_str,
            "index": idx
        }));
    }
    Some(serde_json::json!({ "exports": exports }))
}

// =============================================================================
// Парсер ELF (упрощённый, только 64-bit)
// =============================================================================

fn parse_elf(data: &[u8]) -> Result<BinaryInfo, String> {
    if data.len() < 64 {
        return Err("ELF header too short".to_string());
    }

    // Проверяем EI_CLASS (5-й байт)
    let class = match data[4] {
        1 => "ELF32",
        2 => "ELF64",
        _ => "Unknown",
    };
    let endianness = match data[5] {
        1 => "Little Endian",
        2 => "Big Endian",
        _ => "Unknown",
    };
    let version = data[6] as u32;
    let os_abi = match data[7] {
        0 => "System V",
        1 => "HP-UX",
        2 => "NetBSD",
        3 => "Linux",
        6 => "Solaris",
        9 => "FreeBSD",
        12 => "OpenBSD",
        _ => "Unknown",
    };
    let abi_version = data[8];

    // В зависимости от класса читаем разные поля
    let (entry, phoff, shoff, flags, ehsize, phentsize, phnum, shentsize, shnum, shstrndx) =
        if class == "ELF64" {
            // читаем 64-битные значения
            let entry = read_u64(&data[0x18..0x20])?;
            let phoff = read_u64(&data[0x20..0x28])?;
            let shoff = read_u64(&data[0x28..0x30])?;
            let flags = read_u32(&data[0x30..0x34])?;
            let ehsize = read_u16(&data[0x34..0x36])?;
            let phentsize = read_u16(&data[0x36..0x38])?;
            let phnum = read_u16(&data[0x38..0x3A])?;
            let shentsize = read_u16(&data[0x3A..0x3C])?;
            let shnum = read_u16(&data[0x3C..0x3E])?;
            let shstrndx = read_u16(&data[0x3E..0x40])?;
            (entry, phoff, shoff, flags, ehsize, phentsize, phnum, shentsize, shnum, shstrndx)
        } else {
            // ELF32 (упрощённо)
            let entry = read_u32(&data[0x18..0x1C])? as u64;
            let phoff = read_u32(&data[0x1C..0x20])? as u64;
            let shoff = read_u32(&data[0x20..0x24])? as u64;
            let flags = read_u32(&data[0x30..0x34])?;
            let ehsize = read_u16(&data[0x34..0x36])?;
            let phentsize = read_u16(&data[0x36..0x38])?;
            let phnum = read_u16(&data[0x38..0x3A])?;
            let shentsize = read_u16(&data[0x3A..0x3C])?;
            let shnum = read_u16(&data[0x3C..0x3E])?;
            let shstrndx = read_u16(&data[0x3E..0x40])?;
            (entry, phoff, shoff, flags, ehsize, phentsize, phnum, shentsize, shnum, shstrndx)
        };

    // Чтение секций (если есть)
    let mut sections = Vec::new();
    if shoff > 0 && shnum > 0 {
        let mut strtab_offset = 0;
        let mut strtab_size = 0;
        // Сначала нужно найти строковую таблицу section header string table (shstrndx)
        // Для этого прочитаем заголовок секции с индексом shstrndx
        if shstrndx < shnum {
            let sh_offset = shoff + (shstrndx as u64) * (shentsize as u64);
            if (sh_offset + shentsize as u64) <= data.len() as u64 {
                // читаем имя секции (смещение в строковой таблице)
                // Но чтобы прочитать саму строковую таблицу, нужно сначала прочитать её заголовок
                // для простоты пропускаем, в реальном проекте стоит реализовать полный цикл
            }
        }

        // Пропускаем, но для демонстрации прочитаем несколько первых секций
        for i in 0..shnum.min(10) {
            let sh_offset = shoff + (i as u64) * (shentsize as u64);
            if (sh_offset + shentsize as u64) > data.len() as u64 { break; }
            let offset = sh_offset as usize;
            // читаем поля (зависит от класса)
            let (name_idx, typ, flags64, addr, sec_off, size, link, info, align, entry_size) =
                if class == "ELF64" {
                    let name_idx = read_u32(&data[offset..offset+4])? as u64;
                    let typ = read_u32(&data[offset+4..offset+8])? as u64;
                    let flags64 = read_u64(&data[offset+8..offset+16])?;
                    let addr = read_u64(&data[offset+16..offset+24])?;
                    let sec_off = read_u64(&data[offset+24..offset+32])?;
                    let size = read_u64(&data[offset+32..offset+40])?;
                    let link = read_u32(&data[offset+40..offset+44])?;
                    let info = read_u32(&data[offset+44..offset+48])?;
                    let align = read_u64(&data[offset+48..offset+56])?;
                    let entry_size = read_u64(&data[offset+56..offset+64])?;
                    (name_idx, typ, flags64, addr, sec_off, size, link, info, align, entry_size)
                } else {
                    // ELF32
                    let name_idx = read_u32(&data[offset..offset+4])? as u64;
                    let typ = read_u32(&data[offset+4..offset+8])? as u64;
                    let flags64 = read_u32(&data[offset+8..offset+12])? as u64;
                    let addr = read_u32(&data[offset+12..offset+16])? as u64;
                    let sec_off = read_u32(&data[offset+16..offset+20])? as u64;
                    let size = read_u32(&data[offset+20..offset+24])? as u64;
                    let link = read_u32(&data[offset+24..offset+28])?;
                    let info = read_u32(&data[offset+28..offset+32])?;
                    let align = read_u32(&data[offset+32..offset+36])? as u64;
                    let entry_size = read_u32(&data[offset+36..offset+40])? as u64;
                    (name_idx, typ, flags64, addr, sec_off, size, link, info, align, entry_size)
                };
            // Имя секции читать не будем (требует доступа к строковой таблице)
            sections.push(ElfSection {
                name: format!("#{}", name_idx),
                typ: typ as u32,
                flags: flags64,
                addr,
                offset: sec_off,
                size,
                link,
                info,
                align,
                entry_size,
            });
        }
    }

    // Чтение program headers (сегментов)
    let mut segments = Vec::new();
    if phoff > 0 && phnum > 0 {
        for i in 0..phnum.min(10) {
            let ph_offset = phoff + (i as u64) * (phentsize as u64);
            if (ph_offset + phentsize as u64) > data.len() as u64 { break; }
            let offset = ph_offset as usize;
            let (typ, flags, off, vaddr, paddr, filesz, memsz, align) =
                if class == "ELF64" {
                    let typ = read_u32(&data[offset..offset+4])?;
                    let flags = read_u32(&data[offset+4..offset+8])?;
                    let off = read_u64(&data[offset+8..offset+16])?;
                    let vaddr = read_u64(&data[offset+16..offset+24])?;
                    let paddr = read_u64(&data[offset+24..offset+32])?;
                    let filesz = read_u64(&data[offset+32..offset+40])?;
                    let memsz = read_u64(&data[offset+40..offset+48])?;
                    let align = read_u64(&data[offset+48..offset+56])?;
                    (typ, flags, off, vaddr, paddr, filesz, memsz, align)
                } else {
                    let typ = read_u32(&data[offset..offset+4])?;
                    let off = read_u32(&data[offset+4..offset+8])? as u64;
                    let vaddr = read_u32(&data[offset+8..offset+12])? as u64;
                    let paddr = read_u32(&data[offset+12..offset+16])? as u64;
                    let filesz = read_u32(&data[offset+16..offset+20])? as u64;
                    let memsz = read_u32(&data[offset+20..offset+24])? as u64;
                    let flags = read_u32(&data[offset+24..offset+28])?;
                    let align = read_u32(&data[offset+28..offset+32])? as u64;
                    (typ, flags, off, vaddr, paddr, filesz, memsz, align)
                };
            segments.push(ElfSegment {
                typ,
                flags,
                offset: off,
                vaddr,
                paddr,
                filesz,
                memsz,
                align,
            });
        }
    }

    Ok(BinaryInfo {
        file_type: "ELF".to_string(),
        size: data.len(),
        wasm: None,
        elf: Some(ElfInfo {
            class: class.to_string(),
            endianness: endianness.to_string(),
            version,
            os_abi: os_abi.to_string(),
            abi_version,
            entry_point: entry,
            program_header_offset: phoff,
            section_header_offset: shoff,
            flags,
            header_size: ehsize,
            program_header_entry_size: phentsize,
            program_header_count: phnum,
            section_header_entry_size: shentsize,
            section_header_count: shnum,
            section_header_string_index: shstrndx,
            sections,
            segments,
        }),
    })
}

// Вспомогательные функции чтения чисел из байт
fn read_u64(data: &[u8]) -> Result<u64, String> {
    if data.len() < 8 { return Err("Not enough bytes for u64".to_string()); }
    Ok(u64::from_le_bytes([data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7]]))
}
fn read_u32(data: &[u8]) -> Result<u32, String> {
    if data.len() < 4 { return Err("Not enough bytes for u32".to_string()); }
    Ok(u32::from_le_bytes([data[0], data[1], data[2], data[3]]))
}
fn read_u16(data: &[u8]) -> Result<u16, String> {
    if data.len() < 2 { return Err("Not enough bytes for u16".to_string()); }
    Ok(u16::from_le_bytes([data[0], data[1]]))
}
