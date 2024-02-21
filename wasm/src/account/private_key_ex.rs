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
    types::native::RecordPlaintextNative as Record,
    PrivateKey,
    RecordPlaintext,
};

use core::ops::Deref;
use wasm_bindgen::prelude::*;

use anyhow::Result as AnyhowResult;

use serde::{Deserialize, Serialize};

#[derive(Deserialize, Serialize)]
pub struct RecordData {
    pub record: Record,
    pub serial_number: String,
    #[serde(flatten)]
    pub record_meta: RecordMeta,
}

#[derive(Deserialize)]
pub struct RecordOrgData {
    #[serde(flatten)]
    pub record_meta: RecordMeta,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct RecordMeta {
    pub record_ciphertext: String,
    pub identifier: String,
    pub program_id: String,
    pub height: u32,
    pub timestamp: i64,
    pub block_hash: String,
    pub transaction_id: String,
    pub transition_id: String,
    pub function_name: String,
    pub output_index: u8,
    pub input: Option<Vec<String>>,
    pub address: String,
}

#[wasm_bindgen]
impl PrivateKey {
    #[wasm_bindgen(js_name = "decryptrecords")]
    pub fn decrypt_records(&self, recordstext: &str) -> Result<String, String> {
        let address = self.to_address();
        let address = address.to_string();
        let record_org_datas: Vec<RecordOrgData> = serde_json::from_str(recordstext).unwrap_or_default();
        let viewkey = ViewKey::from_private_key(&self);
        let decrypted_records = record_org_datas
            .iter()
            .filter_map(|record_org_data| decrypt_record_data(self, &viewkey, record_org_data, &address).transpose())
            .collect::<Result<Vec<RecordData>, _>>()
            .unwrap_or_default();
        Ok(serde_json::to_string_pretty(&decrypted_records).unwrap_or_default().replace("\\n", ""))
    }

    #[wasm_bindgen(js_name = "serialnumberrecords")]
    pub fn serial_number_records(&self, recordstext: &str) -> Result<String, String> {
        let record_org_datas: Vec<RecordData> = serde_json::from_str(recordstext).unwrap_or_default();
        let decrypted_records = record_org_datas
            .iter()
            .filter_map(|record_org_data| serial_number_record(self, record_org_data).transpose())
            .collect::<Result<Vec<RecordData>, _>>()
            .unwrap_or_default();
        Ok(serde_json::to_string_pretty(&decrypted_records).unwrap_or_default().replace("\\n", ""))
    }
}

pub fn serial_number_record(private_key: &PrivateKey, record_org: &RecordData) -> AnyhowResult<Option<RecordData>> {
    let program_id = &record_org.record_meta.program_id;
    let record_name = &record_org.record_meta.identifier;

    if let Ok(serial_number) =
        RecordPlaintext::from(record_org.record.clone()).serial_number_string(private_key, program_id, record_name)
    {
        let record_data: RecordData = RecordData {
            record: record_org.record.clone(),
            serial_number,
            record_meta: record_org.record_meta.clone(),
        };
        return Ok(Some(record_data));
    };
    Ok(None)
}

pub fn decrypt_record_data(
    private_key: &PrivateKey,
    viewkey: &ViewKey,
    record_org: &RecordOrgData,
    address: &str,
) -> AnyhowResult<Option<RecordData>> {
    if &record_org.record_meta.address != "" && record_org.record_meta.address != address {
        return Ok(None);
    }

    if let Ok(record) = RecordCiphertext::from_string(&record_org.record_meta.record_ciphertext) {
        if let Ok(plaintext) = record.decrypt(viewkey) {
            let program_id = &record_org.record_meta.program_id;

            let record_name = &record_org.record_meta.identifier;
            if let Ok(serial_number) = plaintext.serial_number_string(private_key, program_id, record_name) {
                let record_data: RecordData = RecordData {
                    record: plaintext.deref().clone(),
                    serial_number,
                    record_meta: record_org.record_meta.clone(),
                };
                return Ok(Some(record_data));
            };
        };
    };

    Ok(None)
}
