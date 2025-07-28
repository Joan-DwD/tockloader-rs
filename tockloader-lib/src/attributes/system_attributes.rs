// Licensed under the Apache License, Version 2.0 or the MIT License.
// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright OXIDOS AUTOMOTIVE 2024.

use byteorder::{ByteOrder, LittleEndian};
use probe_rs::{Core, MemoryInterface};
use tokio_serial::SerialStream;

use crate::bootloader_serial::{issue_command, Command, Response};
use crate::errors::TockloaderError;

use super::decode::{bytes_to_string, decode_attribute};

#[derive(Debug)]
pub struct SystemAttributes {
    pub board: Option<String>,
    pub arch: Option<String>,
    pub appaddr: Option<u64>,
    pub boothash: Option<String>,
    pub bootloader_version: Option<String>,
    pub sentinel: Option<String>,
    pub kernel_version: Option<u64>,
    pub app_mem_start: Option<u32>,
    pub app_mem_len: Option<u32>,
    pub kernel_bin_start: Option<u32>,
    pub kernel_bin_len: Option<u32>,
}

impl SystemAttributes {
    pub(crate) fn new() -> SystemAttributes {
        SystemAttributes {
            board: None,
            arch: None,
            appaddr: None,
            boothash: None,
            bootloader_version: None,
            sentinel: None,
            kernel_version: None,
            app_mem_start: None,
            app_mem_len: None,
            kernel_bin_start: None,
            kernel_bin_len: None,
        }
    }
 /// This function is used to read relevent data regarding the kernel and the board
    /// Firstly we read the bytes between 0x600-0x9FF as 16x 64-byte key-value entries (1024 bytes),
    /// that describe the board and the software running on it.
    /// format per entry:
    /// attribute key (Bytes 0-7), length of the value (Byte 8), value (Bytes 9-63)
    /// More specifically the data (Key-Value) we extract is:
    /// - Key: board, Value: the name of the board
    /// - Key: arch, Value: the architecture of the hardware
    /// - Key: appaddr, Value: the address where the applications are located on the board
    /// - Key: boothash, Value: SHA hash or any other hash methods.
    /// NOTE: There are more slots, up to 15, but they are unused in most boards.
    /// For more information, look into [The Tock Book](https://book.tockos.org/doc/memory_layout)

    /// From the address 0x40E, found within the range 0x400-0x5FF which contains the flags of the bootloader which also contain the bootloader version in an 8-byte null-terminated ASCII string,
    /// we get the:
    /// - bootloader_version (encoded with the utf-8 standard)
    ///
    /// Afterwards we take the last 100 bits of the kernel which is a fixed binary struct format meaning its a group of typed fields of processed bytes with immutable size,
    /// we achieve that by subtracting 100 from the address that represents the start of the applications section(0x40000)
    /// and from those we extract final 100 bytes before application space contain:
    /// - 0-79: is for padding, basically unused.
    /// - 80-84:  app_mem_start (u32, little-endian)
    /// - 84-88:  app_mem_len (u32)
    /// - 88-92:  kernel_mem_start (u32)
    /// - 92-96:  kernel_mem_len (u32)
    /// - 96-100: Sentinel ("TOCK" ASCII)
    /// - 95-96:  Kernel version (u8)
    /// Further explaination can be found here [The Tock Book](https://book.tockos.org/doc/kernel_attributes.html?highlight=attributes#header-format)

    /// Panics
    /// If attribute slots contain invalid UTF-8
    /// If hex address conversion fails
    /// If sentinel value != "TOCK"
    /// On probe-rs communication failures
    ///
    /// Safety
    /// Assumes valid Tock binary layout
    /// Requires aligned memory access
    /// Bootloader must initialize all expected attributes
    pub(crate) fn read_system_attributes_probe(
        board_core: &mut Core,
    ) -> Result<Self, TockloaderError> {
        let mut result = SystemAttributes::new();
        let address = 0x600;
        let mut buf = [0u8; 64 * 16];

        let _ = board_core.read(address, &mut buf);

        let mut data = buf.chunks(64);

        for index_data in 0..data.len() {
            let step = match data.next() {
                Some(data) => data,
                None => break,
            };

            let step_option = decode_attribute(step);

            if let Some(decoded_attributes) = step_option {
                match index_data {
                    0 => {
                        result.board = Some(decoded_attributes.value.to_string());
                    }
                    1 => {
                        result.arch = Some(decoded_attributes.value.to_string());
                    }
                    2 => {
                        result.appaddr = Some(
                            u64::from_str_radix(
                                decoded_attributes
                                    .value
                                    .to_string()
                                    .trim_start_matches("0x"),
                                16,
                            )
                            .map_err(|_| {
                                TockloaderError::MisconfiguredBoard(
                                    "Invalid start address.".to_owned(),
                                )
                            })?,
                        );
                    }
                    3 => {
                        result.boothash = Some(decoded_attributes.value.to_string());
                    }
                    _ => {}
                }
            } else {
                continue;
            }
        }

        let address = 0x40E;

        let mut buf = [0u8; 8];

        let _ = board_core.read_8(address, &mut buf);

        let string = String::from_utf8(buf.to_vec()).map_err(|_| {
            TockloaderError::MisconfiguredBoard(
                "Data may be corrupted. System attribure is not UTF-8.".to_owned(),
            )
        })?;

        let string = string.trim_matches(char::from(0));

        result.bootloader_version = Some(string.to_owned());

        let mut kernel_attr_binary = [0u8; 100];
        board_core
            .read(
                result.appaddr.ok_or(TockloaderError::MisconfiguredBoard(
                    "No start address found.".to_owned(),
                ))? - 100,
                &mut kernel_attr_binary,
            )
            .map_err(TockloaderError::ProbeRsReadError)?;

        let sentinel = bytes_to_string(&kernel_attr_binary[96..100]);
        let kernel_version = LittleEndian::read_uint(&kernel_attr_binary[95..96], 1);

        let app_memory_len = LittleEndian::read_u32(&kernel_attr_binary[84..92]);
        let app_memory_start = LittleEndian::read_u32(&kernel_attr_binary[80..84]);

        let kernel_binary_start = LittleEndian::read_u32(&kernel_attr_binary[68..72]);
        let kernel_binary_len = LittleEndian::read_u32(&kernel_attr_binary[72..76]);

        result.sentinel = Some(sentinel);
        result.kernel_version = Some(kernel_version);
        result.app_mem_start = Some(app_memory_start);
        result.app_mem_len = Some(app_memory_len);
        result.kernel_bin_start = Some(kernel_binary_start);
        result.kernel_bin_len = Some(kernel_binary_len);

        Ok(result)
    }

    // TODO: explain what is happening here
    pub(crate) async fn read_system_attributes_serial(
        port: &mut SerialStream,
    ) -> Result<Self, TockloaderError> {
        let mut result = SystemAttributes::new();

        let mut pkt = (0x600_u32).to_le_bytes().to_vec();
        let length = (1024_u16).to_le_bytes().to_vec();
        for i in length {
            pkt.push(i);
        }

        let (_, buf) = issue_command(
            port,
            Command::ReadRange,
            pkt,
            true,
            64 * 16,
            Response::ReadRange,
        )
        .await?;

        let mut data = buf.chunks(64);

        for index_data in 0..data.len() {
            let step = match data.next() {
                Some(data) => data,
                None => break,
            };

            let step_option = decode_attribute(step);

            if let Some(decoded_attributes) = step_option {
                match index_data {
                    0 => {
                        result.board = Some(decoded_attributes.value.to_string());
                    }
                    1 => {
                        result.arch = Some(decoded_attributes.value.to_string());
                    }
                    2 => {
                        result.appaddr = Some(
                            u64::from_str_radix(
                                decoded_attributes
                                    .value
                                    .to_string()
                                    .trim_start_matches("0x"),
                                16,
                            )
                            .map_err(|_| {
                                TockloaderError::MisconfiguredBoard(
                                    "Invalid start address.".to_owned(),
                                )
                            })?,
                        );
                    }
                    3 => {
                        result.boothash = Some(decoded_attributes.value.to_string());
                    }
                    _ => {}
                }
            } else {
                continue;
            }
        }

        let mut pkt = (0x40E_u32).to_le_bytes().to_vec();
        let length = (8_u16).to_le_bytes().to_vec();
        for i in length {
            pkt.push(i);
        }

        let (_, buf) =
            issue_command(port, Command::ReadRange, pkt, true, 8, Response::ReadRange).await?;

        let string = String::from_utf8(buf).map_err(|_| {
            TockloaderError::MisconfiguredBoard(
                "Data may be corrupted. System attribure is not UTF-8.".to_owned(),
            )
        })?;

        let string = string.trim_matches(char::from(0));

        result.bootloader_version = Some(string.to_owned());

        let mut pkt = ((result.appaddr.ok_or(TockloaderError::MisconfiguredBoard(
            "No start address found.".to_owned(),
        ))? - 100) as u32)
            .to_le_bytes()
            .to_vec();
        let length = (100_u16).to_le_bytes().to_vec();
        for i in length {
            pkt.push(i);
        }

        let (_, kernel_attr_binary) = issue_command(
            port,
            Command::ReadRange,
            pkt,
            true,
            100,
            Response::ReadRange,
        )
        .await?;

        let sentinel = bytes_to_string(&kernel_attr_binary[96..100]);
        let kernel_version = LittleEndian::read_uint(&kernel_attr_binary[95..96], 1);

        let app_memory_len = LittleEndian::read_u32(&kernel_attr_binary[84..92]);
        let app_memory_start = LittleEndian::read_u32(&kernel_attr_binary[80..84]);

        let kernel_binary_start = LittleEndian::read_u32(&kernel_attr_binary[68..72]);
        let kernel_binary_len = LittleEndian::read_u32(&kernel_attr_binary[72..76]);

        result.sentinel = Some(sentinel);
        result.kernel_version = Some(kernel_version);
        result.app_mem_start = Some(app_memory_start);
        result.app_mem_len = Some(app_memory_len);
        result.kernel_bin_start = Some(kernel_binary_start);
        result.kernel_bin_len = Some(kernel_binary_len);

        Ok(result)
    }
}
