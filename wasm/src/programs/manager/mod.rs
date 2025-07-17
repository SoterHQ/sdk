// Copyright (C) 2019-2025 Provable Inc.
// This file is part of the Provable SDK library.

// The Provable SDK library is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// The Provable SDK library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with the Provable SDK library. If not, see <https://www.gnu.org/licenses/>.

pub mod deploy;
pub mod execute;
pub mod join;
pub mod split;
pub mod transfer;

const DEFAULT_URL: &str = "https://api.explorer.provable.com/v1";

use crate::{
    KeyPair,
    PrivateKey,
    ProvingKey,
    RecordPlaintext,
    RecordCiphertext,
    ViewKey,
    VerifyingKey,
    log,
    types::native::{
        IdentifierNative,
        ProcessNative,
        ProgramIDNative,
        ProgramNative,
        ProvingKeyNative,
        QueryNative,
        VerifyingKeyNative,
        cost_in_microcredits_v2,
        deployment_cost,
    },
};
use snarkvm_synthesizer_program::StackKeys;

use js_sys::{Object, Reflect};
use std::str::FromStr;
use wasm_bindgen::prelude::wasm_bindgen;

#[wasm_bindgen]
#[derive(Clone)]
pub struct ProgramManager;

#[wasm_bindgen]
impl ProgramManager {
    /// Validate that an amount being paid from a record is greater than zero and that the record
    /// has enough credits to pay the amount
    pub(crate) fn validate_amount(microcredits: u64, amount: &RecordPlaintext, fee: bool) -> Result<u64, String> {
        let name = if fee { "Fee" } else { "Amount" };

        if amount.microcredits() < microcredits {
            return Err(format!("{name} record does not have enough credits to pay the specified fee"));
        }

        Ok(microcredits)
    }

    pub(crate) fn parse_record(private_key: &PrivateKey, record: String) -> Result<RecordPlaintext, String> {
        match record.starts_with("record1") {
            true => {
                // Parse the ciphertext.
                let ciphertext =
                    RecordCiphertext::from_str(&record).map_err(|_| "RecordCiphertext from_str".to_string())?;
                // Derive the view key.
                let view_key: ViewKey = private_key.to_view_key();
                // Decrypt the ciphertext.
                // ciphertext.decrypt(view_key)
                ciphertext.decrypt(&view_key)
            }
            false => RecordPlaintext::from_str(&record).map_err(|_| "RecordPlaintext from_str".to_string()),
        }
    }

    /// Synthesize proving and verifying keys for a program
    ///
    /// @param program {string} The program source code of the program to synthesize keys for
    /// @param function_id {string} The function to synthesize keys for
    /// @param inputs {Array} The inputs to the function
    /// @param imports {Object | undefined} The imports for the program
    #[wasm_bindgen(js_name = "synthesizeKeyPair")]
    pub async fn synthesize_keypair(
        private_key: &PrivateKey,
        program: &str,
        function_id: &str,
        inputs: js_sys::Array,
        imports: Option<Object>,
    ) -> Result<KeyPair, String> {
        ProgramManager::execute_function_offline(
            private_key,
            program,
            function_id,
            inputs,
            false,
            true,
            imports,
            None,
            None,
            None,
            None,
        )
        .await?
        .get_keys()
    }

    /// Check if a process contains a keypair for a specific function
    pub(crate) fn contains_key(
        process: &ProcessNative,
        program_id: &ProgramIDNative,
        function_id: &IdentifierNative,
    ) -> bool {
        process.get_stack(program_id).map_or_else(
            |_| false,
            |stack| stack.contains_proving_key(function_id) && stack.contains_verifying_key(function_id),
        )
    }

    /// Resolve imports for a program in depth first search order
    pub(crate) fn resolve_imports(
        process: &mut ProcessNative,
        program: &ProgramNative,
        imports: Option<Object>,
    ) -> Result<(), String> {
        if let Some(imports) = imports {
            program.imports().keys().try_for_each(|program_id| {
                // Get the program string
                let program_id = program_id.to_string();
                if let Some(import_string) = Reflect::get(&imports, &program_id.as_str().into())
                    .map_err(|_| "Program import not found in imports provided".to_string())?
                    .as_string()
                {
                    if &program_id != "credits.aleo" {
                        log(&format!("Importing program: {}", program_id));
                        let import = ProgramNative::from_str(&import_string).map_err(|err| err.to_string())?;
                        // If the program has imports, add them
                        Self::resolve_imports(process, &import, Some(imports.clone()))?;
                        // If the process does not already contain the program, add it
                        if !process.contains_program(import.id()) {
                            process.add_program(&import).map_err(|err| err.to_string())?;
                        }
                    }
                }
                Ok::<(), String>(())
            })
        } else {
            Ok(())
        }
    }

    pub(crate) fn validate_fee_record(
        fee_record: &Option<RecordPlaintext>,
        minimum_execution_cost: u64,
        priority_fee_microcredits: u64,
    ) -> Result<(), String> {
        let total_fee = priority_fee_microcredits.saturating_add(minimum_execution_cost);
        if let Some(fee_record) = fee_record {
            log("Validating the fee record");
            if fee_record.microcredits() < total_fee {
                return Err(format!(
                    "Fee record does not have enough credits to pay for a fee of {} credits. (base fee: {} credits - priority fee: {} credits)",
                    total_fee as f64 / 1_000_000.0,
                    minimum_execution_cost as f64 / 1_000_000.0,
                    priority_fee_microcredits as f64 / 1_000_000.0,
                ));
            }
        }
        Ok(())
    }
}
