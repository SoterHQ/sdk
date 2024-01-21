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

use super::*;

use crate::{
    authorize_fee,
    authorize_program,
    execute_fee,
    execute_program,
    log,
    process_inputs,
    Authorization,
    OfflineQuery,
    PrivateKey,
    Transaction,
};

use crate::types::native::{
    CurrentAleo,
    IdentifierNative,
    ProcessNative,
    ProgramNative,
    RecordPlaintextNative,
    TransactionNative,
};
use js_sys::Array;
use rand::{rngs::StdRng, SeedableRng};
use std::{ops::Add, str::FromStr};

#[wasm_bindgen]
impl ProgramManager {
    /// Send credits from one Aleo account to another
    ///
    /// @param private_key The private key of the sender
    /// @param amount_credits The amount of credits to send
    /// @param recipient The recipient of the transaction
    /// @param transfer_type The type of the transfer (options: "private", "public", "private_to_public", "public_to_private")
    /// @param amount_record The record to fund the amount from
    /// @param fee_credits The amount of credits to pay as a fee
    /// @param fee_record The record to spend the fee from
    /// @param url The url of the Aleo network node to send the transaction to
    /// @param transfer_verifying_key (optional) Provide a verifying key to use for the transfer
    /// function
    /// @param fee_proving_key (optional) Provide a proving key to use for the fee execution
    /// @param fee_verifying_key (optional) Provide a verifying key to use for the fee execution
    /// @returns {Transaction | Error}
    #[wasm_bindgen(js_name = buildTransferTransaction)]
    #[allow(clippy::too_many_arguments)]
    pub async fn transfer(
        private_key: &PrivateKey,
        amount_microcredits: u64,
        recipient: &str,
        transfer_type: &str,
        amount_record: Option<String>,
        priority_fee_in_microcredits: u64,
        fee_record: Option<String>,
        url: Option<String>,
        transfer_proving_key: Option<ProvingKey>,
        transfer_verifying_key: Option<VerifyingKey>,
        fee_proving_key: Option<ProvingKey>,
        fee_verifying_key: Option<VerifyingKey>,
        offline_query: Option<OfflineQuery>,
    ) -> Result<Transaction, String> {
        log("Executing transfer program");
        // Prepare the fees.
        let amount_record = match amount_record {
            Some(amount_record) => Some(
                Self::parse_record(&private_key, amount_record).map_err(|_| "RecordCiphertext from_str".to_string())?,
            ),
            None => None,
        };

        // Prepare the fees.
        let fee_record = match fee_record {
            Some(fee_record) => Some(
                Self::parse_record(&private_key, fee_record).map_err(|_| "RecordCiphertext from_str".to_string())?,
            ),
            None => None,
        };

        let priority_fee_in_microcredits = match &fee_record {
            Some(fee_record) => Self::validate_amount(priority_fee_in_microcredits, fee_record, true)?,
            None => priority_fee_in_microcredits,
        };

        let amount_microcredits = match &amount_record {
            Some(amount_record) => Self::validate_amount(amount_microcredits, amount_record, true)?,
            None => amount_microcredits,
        };

        log("Setup the program and inputs");
        let node_url = url.as_deref().unwrap_or(DEFAULT_URL);
        let program = ProgramNative::credits().unwrap().to_string();
        let rng = &mut StdRng::from_entropy();

        log("Transfer Type is:");
        log(transfer_type);

        let (transfer_type, inputs) = match transfer_type {
            "private" | "transfer_private" | "transferPrivate" => {
                if amount_record.is_none() {
                    return Err("Amount record must be provided for private transfers".to_string());
                }
                let inputs = Array::new_with_length(3);
                inputs.set(0u32, wasm_bindgen::JsValue::from_str(&amount_record.unwrap().to_string()));
                inputs.set(1u32, wasm_bindgen::JsValue::from_str(recipient));
                inputs.set(2u32, wasm_bindgen::JsValue::from_str(&amount_microcredits.to_string().add("u64")));
                ("transfer_private", inputs)
            }
            "private_to_public" | "privateToPublic" | "transfer_private_to_public" | "transferPrivateToPublic" => {
                if amount_record.is_none() {
                    return Err("Amount record must be provided for private transfers".to_string());
                }
                let inputs = Array::new_with_length(3);
                inputs.set(0u32, wasm_bindgen::JsValue::from_str(&amount_record.unwrap().to_string()));
                inputs.set(1u32, wasm_bindgen::JsValue::from_str(recipient));
                inputs.set(2u32, wasm_bindgen::JsValue::from_str(&amount_microcredits.to_string().add("u64")));
                ("transfer_private_to_public", inputs)
            }
            "public" | "transfer_public" | "transferPublic" => {
                let inputs = Array::new_with_length(2);
                inputs.set(0u32, wasm_bindgen::JsValue::from_str(recipient));
                inputs.set(1u32, wasm_bindgen::JsValue::from_str(&amount_microcredits.to_string().add("u64")));
                ("transfer_public", inputs)
            }
            "public_to_private" | "publicToPrivate" | "transfer_public_to_private" | "transferPublicToPrivate" => {
                let inputs = Array::new_with_length(2);
                inputs.set(0u32, wasm_bindgen::JsValue::from_str(recipient));
                inputs.set(1u32, wasm_bindgen::JsValue::from_str(&amount_microcredits.to_string().add("u64")));
                ("transfer_public_to_private", inputs)
            }
            _ => return Err("Invalid transfer type".to_string()),
        };

        let mut process_native = ProcessNative::load_web().map_err(|err| err.to_string())?;
        let process = &mut process_native;
        let fee_identifier = if fee_record.is_some() {
            IdentifierNative::from_str("fee_private").map_err(|e| e.to_string())?
        } else {
            IdentifierNative::from_str("fee_public").map_err(|e| e.to_string())?
        };
        let stack = process.get_stack("credits.aleo").map_err(|e| e.to_string())?;
        if !stack.contains_proving_key(&fee_identifier) && fee_proving_key.is_some() && fee_verifying_key.is_some() {
            let fee_proving_key = fee_proving_key.clone().unwrap();
            let fee_verifying_key = fee_verifying_key.clone().unwrap();
            stack
                .insert_proving_key(&fee_identifier, ProvingKeyNative::from(fee_proving_key))
                .map_err(|e| e.to_string())?;
            stack
                .insert_verifying_key(&fee_identifier, VerifyingKeyNative::from(fee_verifying_key))
                .map_err(|e| e.to_string())?;
        }

        log("Executing transfer function");
        let (_, mut trace) = execute_program!(
            process,
            process_inputs!(inputs),
            &program,
            transfer_type,
            private_key,
            transfer_proving_key,
            transfer_verifying_key,
            rng
        );

        log("Preparing the inclusion proof for the transfer execution");
        if let Some(offline_query) = offline_query.as_ref() {
            trace.prepare_async(offline_query.clone()).await.map_err(|err| err.to_string())?;
        } else {
            let query = QueryNative::from(node_url);
            trace.prepare_async(query).await.map_err(|err| err.to_string())?;
        }

        let program =
            ProgramNative::from_str(&program).map_err(|_| "The program ID provided was invalid".to_string())?;

        let locator = program.id().to_string().add("/").add(&transfer_type);
        log(&format!("transfer trace prove_execution locator {locator}"));
        // Prove the execution and fee
        let execution = trace.prove_execution::<CurrentAleo, _>(&locator, rng).map_err(|e| e.to_string())?;
        let execution_id = execution.to_execution_id().map_err(|e| e.to_string())?;

        log("Verifying the transfer execution");
        process.verify_execution(&execution).map_err(|err| err.to_string())?;

        // Get the storage cost in bytes for the program execution
        let storage_cost = execution.size_in_bytes().map_err(|e| e.to_string())?;

        // Compute the finalize cost in microcredits.
        let mut finalize_cost = 0u64;
        // Iterate over the transitions to accumulate the finalize cost.
        for transition in execution.transitions() {
            // Retrieve the function name.
            let function_name = transition.function_name();
            // Retrieve the finalize cost.
            let cost = match program.get_function(function_name).map_err(|e| e.to_string())?.finalize_logic() {
                Some(finalize) => cost_in_microcredits(finalize).map_err(|e| e.to_string())?,
                None => continue,
            };
            // Accumulate the finalize cost.
            finalize_cost = finalize_cost
                .checked_add(cost)
                .ok_or("The finalize cost computation overflowed for an execution".to_string())?;
        }

        let minimum_fee_cost = finalize_cost + storage_cost;

        log("Executing the fee");
        let fee = execute_fee!(
            process,
            private_key,
            fee_record,
            minimum_fee_cost,
            priority_fee_in_microcredits,
            node_url,
            fee_proving_key,
            fee_verifying_key,
            execution_id,
            rng,
            offline_query
        );

        log("Creating execution transaction for transfer");
        let transaction = TransactionNative::from_execution(execution, Some(fee)).map_err(|err| err.to_string())?;
        Ok(Transaction::from(transaction))
    }

    /// Send credits from one Aleo account to another
    ///
    /// @param private_key The private key of the sender
    /// @param amount_credits The amount of credits to send
    /// @param recipient The recipient of the transaction
    /// @param transfer_type The type of the transfer (options: "private", "public", "private_to_public", "public_to_private")
    /// @param amount_record The record to fund the amount from
    /// @param fee_credits The amount of credits to pay as a fee
    /// @param fee_record The record to spend the fee from
    /// @param url The url of the Aleo network node to send the transaction to
    /// @param transfer_verifying_key (optional) Provide a verifying key to use for the transfer
    /// function
    /// @param fee_proving_key (optional) Provide a proving key to use for the fee execution
    /// @param fee_verifying_key (optional) Provide a verifying key to use for the fee execution
    /// @returns {Transaction | Error}
    #[wasm_bindgen(js_name = buildTransferAuthorizes)]
    #[allow(clippy::too_many_arguments)]
    pub async fn transfer_authorize(
        private_key: &PrivateKey,
        amount_microcredits: u64,
        recipient: &str,
        transfer_type: &str,
        amount_record: Option<String>,
        minimum_fee_cost: u64,
        priority_fee_in_microcredits: u64,
        fee_record: Option<String>,
        transfer_proving_key: Option<ProvingKey>,
        transfer_verifying_key: Option<VerifyingKey>,
        fee_proving_key: Option<ProvingKey>,
        fee_verifying_key: Option<VerifyingKey>,
    ) -> Result<String, String> {
        log("Transfer authorize");
        // Prepare the fees.
        let amount_record = match amount_record {
            Some(amount_record) => Some(
                Self::parse_record(&private_key, amount_record).map_err(|_| "RecordCiphertext from_str".to_string())?,
            ),
            None => None,
        };

        // Prepare the fees.
        let fee_record = match fee_record {
            Some(fee_record) => Some(
                Self::parse_record(&private_key, fee_record).map_err(|_| "RecordCiphertext from_str".to_string())?,
            ),
            None => None,
        };

        let priority_fee_in_microcredits = match &fee_record {
            Some(fee_record) => Self::validate_amount(priority_fee_in_microcredits, fee_record, true)?,
            None => priority_fee_in_microcredits,
        };

        let amount_microcredits = match &amount_record {
            Some(amount_record) => Self::validate_amount(amount_microcredits, amount_record, true)?,
            None => amount_microcredits,
        };

        log("Setup the program and inputs");
        let program = ProgramNative::credits().unwrap().to_string();
        let rng = &mut StdRng::from_entropy();

        log("Transfer Type is:");
        log(transfer_type);

        let (transfer_type, inputs) = match transfer_type {
            "private" | "transfer_private" | "transferPrivate" => {
                if amount_record.is_none() {
                    return Err("Amount record must be provided for private transfers".to_string());
                }
                let inputs = Array::new_with_length(3);
                inputs.set(0u32, wasm_bindgen::JsValue::from_str(&amount_record.unwrap().to_string()));
                inputs.set(1u32, wasm_bindgen::JsValue::from_str(recipient));
                inputs.set(2u32, wasm_bindgen::JsValue::from_str(&amount_microcredits.to_string().add("u64")));
                ("transfer_private", inputs)
            }
            "private_to_public" | "privateToPublic" | "transfer_private_to_public" | "transferPrivateToPublic" => {
                if amount_record.is_none() {
                    return Err("Amount record must be provided for private transfers".to_string());
                }
                let inputs = Array::new_with_length(3);
                inputs.set(0u32, wasm_bindgen::JsValue::from_str(&amount_record.unwrap().to_string()));
                inputs.set(1u32, wasm_bindgen::JsValue::from_str(recipient));
                inputs.set(2u32, wasm_bindgen::JsValue::from_str(&amount_microcredits.to_string().add("u64")));
                ("transfer_private_to_public", inputs)
            }
            "public" | "transfer_public" | "transferPublic" => {
                let inputs = Array::new_with_length(2);
                inputs.set(0u32, wasm_bindgen::JsValue::from_str(recipient));
                inputs.set(1u32, wasm_bindgen::JsValue::from_str(&amount_microcredits.to_string().add("u64")));
                ("transfer_public", inputs)
            }
            "public_to_private" | "publicToPrivate" | "transfer_public_to_private" | "transferPublicToPrivate" => {
                let inputs = Array::new_with_length(2);
                inputs.set(0u32, wasm_bindgen::JsValue::from_str(recipient));
                inputs.set(1u32, wasm_bindgen::JsValue::from_str(&amount_microcredits.to_string().add("u64")));
                ("transfer_public_to_private", inputs)
            }
            _ => return Err("Invalid transfer type".to_string()),
        };

        let mut process_native = ProcessNative::load_web().map_err(|err| err.to_string())?;
        let process = &mut process_native;
        let fee_identifier = if fee_record.is_some() {
            IdentifierNative::from_str("fee_private").map_err(|e| e.to_string())?
        } else {
            IdentifierNative::from_str("fee_public").map_err(|e| e.to_string())?
        };
        let stack = process.get_stack("credits.aleo").map_err(|e| e.to_string())?;
        if !stack.contains_proving_key(&fee_identifier) && fee_proving_key.is_some() && fee_verifying_key.is_some() {
            let fee_proving_key = fee_proving_key.clone().unwrap();
            let fee_verifying_key = fee_verifying_key.clone().unwrap();
            stack
                .insert_proving_key(&fee_identifier, ProvingKeyNative::from(fee_proving_key))
                .map_err(|e| e.to_string())?;
            stack
                .insert_verifying_key(&fee_identifier, VerifyingKeyNative::from(fee_verifying_key))
                .map_err(|e| e.to_string())?;
        }

        let mut authorizations: Vec<Authorization> = Vec::new();
        log("Executing transfer authorize function");
        let authorize_program = authorize_program!(
            process,
            process_inputs!(inputs),
            &program,
            transfer_type,
            private_key,
            transfer_proving_key,
            transfer_verifying_key,
            rng
        );

        log("Creating execution_id for transfer");
        let execution_id = *TransactionNative::transitions_tree(authorize_program.transitions().values(), &None)
            .map_err(|e| e.to_string())?
            .root();

        authorizations.push(Authorization::from(authorize_program));

        let authorize_fee = authorize_fee!(
            process,
            private_key,
            fee_record,
            minimum_fee_cost,
            priority_fee_in_microcredits,
            fee_proving_key,
            fee_verifying_key,
            execution_id,
            rng
        );
        authorizations.push(Authorization::from(authorize_fee));

        Ok(serde_json::to_string_pretty(&authorizations).unwrap_or_default())
    }
}
