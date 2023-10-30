// Copyright (C) 2019-2023 Aleo Systems Inc.
// This file is part of the Aleo SDK library.

// The Aleo SDK library is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// The Aleo SDK library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with the Aleo SDK library. If not, see <https://www.gnu.org/licenses/>.

use crate::{
    account::ViewKey,
    record::RecordCiphertext,
    types::{CurrentNetwork, Network, Field, RecordPlaintextNative as Record}, PrivateKey,
};

use core::ops::Deref;
use wasm_bindgen::prelude::*;

use serde::{Deserialize, Serialize};


#[derive(Serialize)]
pub struct OldRecordData<N: Network> {
    record: Record,
    transactionid: N::TransitionID,
    serial_number: Field<CurrentNetwork>,
}

#[derive(Serialize)]
pub struct RecordData {
    record: Record,
    identifier: String,
    serial_number: String,
    program_id: String,
    height: u32,
    timestamp: i64,
    block_hash: String,
    transaction_id: String,
    transition_id: String,
    function_name: String,
    output_index: u8,
    input: Option<Vec<String>>,
}

#[derive(Deserialize)]
pub struct RecordOrgData {
    record_ciphertext: String,
    identifier: String,
    program_id: String,
    height: u32,
    timestamp: i64,
    block_hash: String,
    transaction_id: String,
    transition_id: String,
    function_name: String,
    output_index: u8,
    input: Option<Vec<String>>,
}

#[wasm_bindgen]
impl PrivateKey {

    #[wasm_bindgen(js_name = "decryptrecords")]
    pub fn decrypt_records(&self, recordstext: &str) -> Result<String, String> {
        let record_org_datas: Vec<RecordOrgData> = serde_json::from_str(recordstext).unwrap_or_default();
        let mut records = Vec::new();
        for record_org in record_org_datas {
            if let Ok(record) = RecordCiphertext::from_string(&record_org.record_ciphertext) {
                if let Ok(plaintext) = record.decrypt(&ViewKey::from_private_key(&self)) {
                    let program_id = record_org.program_id.clone();

                    let record_name = &record_org.identifier;
                    if let Ok(serial_number) = plaintext.serial_number_string(&self, &program_id, record_name) {
                        let record_data: RecordData = RecordData {
                            record: plaintext.deref().clone(),
                            identifier: record_org.identifier,
                            serial_number,
                            program_id,
                            height: record_org.height,
                            timestamp: record_org.timestamp,
                            block_hash: record_org.block_hash,
                            transaction_id: record_org.transaction_id,
                            transition_id: record_org.transition_id,
                            function_name: record_org.function_name,
                            output_index: record_org.output_index,
                            input: record_org.input,
                        };
                        records.push(record_data)
                    };
                };
            };
        }
        Ok(serde_json::to_string_pretty(&records).unwrap_or_default().replace("\\n", ""))
    }
}