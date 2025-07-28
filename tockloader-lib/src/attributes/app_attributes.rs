// Licensed under the Apache License, Version 2.0 or the MIT License.
// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright OXIDOS AUTOMOTIVE 2024.

use probe_rs::{Core, MemoryInterface};

use tbf_parser::parse::{parse_tbf_footer, parse_tbf_header, parse_tbf_header_lengths};
use tbf_parser::types::{TbfFooterV2Credentials, TbfHeader};
use tbf_parser::{self};
use tokio_serial::SerialStream;

use crate::bootloader_serial::{issue_command, Command, Response};
use crate::errors::TockloaderError;

/// Structure used to package an app's header and footer data.
/// This structure is used to package together all relevant information like metadata about an app. 
/// The information is usually stored within a [TbfHeader], and one or more [TbfFooters](TbfFooterV2Credentials).
/// For more details see <https://book.tockos.org/doc/tock_binary_format>
#[derive(Debug)]
pub struct AppAttributes {
    pub tbf_header: TbfHeader,
    pub tbf_footers: Vec<TbfFooter>,
}

/// Structure used to package a footers credential data and the size of the footer.
/// This is where credentials of the footer is stored
#[derive(Debug)]
pub struct TbfFooter {
    pub credentials: TbfFooterV2Credentials,
    pub size: u32,
}

impl TbfFooter {
    pub fn new(credentials: TbfFooterV2Credentials, size: u32) -> TbfFooter {
        TbfFooter { credentials, size }
    }
}

// TODO(george-cosma): Could take advantages of the trait rework

impl AppAttributes {
    pub(crate) fn new(header_data: TbfHeader, footers_data: Vec<TbfFooter>) -> AppAttributes {
        AppAttributes {
            tbf_header: header_data,
            tbf_footers: footers_data,
        }
    }
    /// from all the applications flashed on the board.
    /// The function below is used to retrieve header and footer data
    /// Starting from the 0x40000 address,
    /// we read the very first 8 bytes to determine:
    /// - tbf-version
    /// - header_size
    /// - total_size
    /// using the parse_tbf_header_lengths function,
    /// Afterward, with the header_size we just read,
    /// we read the the rest of the header information using the same function
    /// then, we save the end of our binary app which marks the total size of the app and the start of the footer.
    /// Now, we calculate the total size of the footer step by step:
    /// 1. Using the known end of the binary (from the header's total_size),
    /// 2. Subtracting the size of any previously read footers,
    /// 3. Finally, accounting for the extra 4 bytes (2 bytes for type, 2 for length) for each footer entry.
    /// We compute the exact offset where the current footer begins using the below relation:
    ///     footer_offset = binary_offset + previous_footer_size + 4
    /// Using this offset, we read the correct number of bytes from memory,
    /// construct a TbfFooter struct from the raw bytes, and store it.
    /// Once all footers for an app are gathered,
    /// we wrap the header, footers, and other metadata into an `AppAttributes` struct,
    /// and push it into the apps_details vector, which holds info for all flashed applications
    pub(crate) fn read_apps_data_probe(
        board_core: &mut Core,
        addr: u64,
    ) -> Result<Vec<AppAttributes>, TockloaderError> {
        let mut appaddr: u64 = addr;
        let mut apps_counter = 0;
        let mut apps_details: Vec<AppAttributes> = vec![];

        loop {
            let mut appdata = vec![0u8; 8];

            board_core
                .read(appaddr, &mut appdata)
                .map_err(TockloaderError::ProbeRsReadError)?;

            let tbf_version: u16;
            let header_size: u16;
            let total_size: u32;

            match parse_tbf_header_lengths(
                &appdata
                    .try_into()
                    .expect("Buffer length must be at least 8 bytes long."),
            ) {
                Ok(data) => {
                    tbf_version = data.0;
                    header_size = data.1;
                    total_size = data.2;
                }
                _ => return Ok(apps_details),
            };

            let mut header_data = vec![0u8; header_size as usize];

            board_core
                .read(appaddr, &mut header_data)
                .map_err(TockloaderError::ProbeRsReadError)?;
            let header = parse_tbf_header(&header_data, tbf_version)
                .map_err(TockloaderError::ParsingError)?;

            let binary_end_offset = header.get_binary_end();

            let mut footers: Vec<TbfFooter> = vec![];
            let total_footers_size = total_size - binary_end_offset;
            let mut footer_offset = binary_end_offset;
            let mut footer_number = 0;

            loop {
                let mut appfooter =
                    vec![0u8; (total_footers_size - (footer_offset - binary_end_offset)) as usize];

                board_core
                    .read(appaddr + footer_offset as u64, &mut appfooter)
                    .map_err(TockloaderError::ProbeRsReadError)?;

                let footer_info =
                    parse_tbf_footer(&appfooter).map_err(TockloaderError::ParsingError)?;

                footers.insert(footer_number, TbfFooter::new(footer_info.0, footer_info.1));

                footer_number += 1;
                footer_offset += footer_info.1 + 4;

                if footer_offset == total_size {
                    break;
                }
            }

            let details: AppAttributes = AppAttributes::new(header, footers);

            apps_details.insert(apps_counter, details);
            apps_counter += 1;
            appaddr += total_size as u64;
        }
    }

    // TODO: Document this function
    pub(crate) async fn read_apps_data_serial(
        port: &mut SerialStream,
        addr: u64,
    ) -> Result<Vec<AppAttributes>, TockloaderError> {
        let mut appaddr: u64 = addr;
        let mut apps_counter = 0;
        let mut apps_details: Vec<AppAttributes> = vec![];

        loop {
            let mut pkt = (appaddr as u32).to_le_bytes().to_vec();
            let length = (8_u16).to_le_bytes().to_vec();
            for i in length {
                pkt.push(i);
            }

            let (_, appdata) =
                issue_command(port, Command::ReadRange, pkt, true, 8, Response::ReadRange).await?;

            let tbf_version: u16;
            let header_size: u16;
            let total_size: u32;

            match parse_tbf_header_lengths(
                &appdata[0..8]
                    .try_into()
                    .expect("Buffer length must be at least 8 bytes long."),
            ) {
                Ok(data) => {
                    tbf_version = data.0;
                    header_size = data.1;
                    total_size = data.2;
                }
                _ => break,
            };

            let mut pkt = (appaddr as u32).to_le_bytes().to_vec();
            let length = (header_size).to_le_bytes().to_vec();
            for i in length {
                pkt.push(i);
            }

            let (_, header_data) = issue_command(
                port,
                Command::ReadRange,
                pkt,
                true,
                header_size.into(),
                Response::ReadRange,
            )
            .await?;

            let header = parse_tbf_header(&header_data, tbf_version)
                .map_err(TockloaderError::ParsingError)?;
            let binary_end_offset = header.get_binary_end();

            let mut footers: Vec<TbfFooter> = vec![];
            let total_footers_size = total_size - binary_end_offset;
            let mut footer_offset = binary_end_offset;
            let mut footer_number = 0;

            loop {
                let mut pkt = (appaddr as u32 + footer_offset).to_le_bytes().to_vec();
                let length = ((total_footers_size - (footer_offset - binary_end_offset)) as u16)
                    .to_le_bytes()
                    .to_vec();
                for i in length {
                    pkt.push(i);
                }

                let (_, appfooter) = issue_command(
                    port,
                    Command::ReadRange,
                    pkt,
                    true,
                    (total_footers_size - (footer_offset - binary_end_offset)) as usize,
                    Response::ReadRange,
                )
                .await?;

                let footer_info =
                    parse_tbf_footer(&appfooter).map_err(TockloaderError::ParsingError)?;

                footers.insert(footer_number, TbfFooter::new(footer_info.0, footer_info.1));

                footer_number += 1;
                footer_offset += footer_info.1 + 4;

                if footer_offset == total_size {
                    break;
                }
            }

            let details: AppAttributes = AppAttributes::new(header, footers);

            apps_details.insert(apps_counter, details);
            apps_counter += 1;
            appaddr += total_size as u64;
        }
        Ok(apps_details)
    }
}
