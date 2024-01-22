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
    authorize_fee, authorize_program, execute_fee, execute_program, log, process_inputs, Authorization, OfflineQuery, PrivateKey, Transaction
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
use std::str::FromStr;

#[wasm_bindgen]
impl ProgramManager {
    /// Join two records together to create a new record with an amount of credits equal to the sum
    /// of the credits of the two original records
    ///
    /// @param private_key The private key of the sender
    /// @param record_1 The first record to combine
    /// @param record_2 The second record to combine
    /// @param fee_credits The amount of credits to pay as a fee
    /// @param fee_record The record to spend the fee from
    /// @param url The url of the Aleo network node to send the transaction to
    /// @param join_proving_key (optional) Provide a proving key to use for the join function
    /// @param join_verifying_key (optional) Provide a verifying key to use for the join function
    /// @param fee_proving_key (optional) Provide a proving key to use for the fee execution
    /// @param fee_verifying_key (optional) Provide a verifying key to use for the fee execution
    /// @returns {Transaction | Error} Transaction object
    #[wasm_bindgen(js_name = buildJoinTransaction)]
    #[allow(clippy::too_many_arguments)]
    pub async fn join(
        private_key: &PrivateKey,
        record_1: String,
        record_2: String,
        priority_fee_in_microcredits: u64,
        fee_record: Option<String>,
        url: Option<String>,
        join_proving_key: Option<ProvingKey>,
        join_verifying_key: Option<VerifyingKey>,
        fee_proving_key: Option<ProvingKey>,
        fee_verifying_key: Option<VerifyingKey>,
        offline_query: Option<OfflineQuery>,
    ) -> Result<Transaction, String> {
        log("Executing join program");
        let fee_record = match fee_record {
            Some(fee_record) => {
                Some(Self::parse_record(&private_key, fee_record).map_err(|_| "RecordCiphertext from_str".to_string())?)
            }
            None => None,
        };

        let priority_fee = match &fee_record {
            Some(fee_record) => Self::validate_amount(priority_fee_in_microcredits, fee_record, true)?,
            None => priority_fee_in_microcredits,
        };
        let rng = &mut StdRng::from_entropy();

        let record_1 = Self::parse_record(&private_key, record_1).map_err(|_| "RecordCiphertext from_str".to_string())?;
        let record_2 = Self::parse_record(&private_key, record_2).map_err(|_| "RecordCiphertext from_str".to_string())?;

        log("Setup program and inputs");
        let node_url = url.as_deref().unwrap_or(DEFAULT_URL);
        let program = ProgramNative::credits().unwrap().to_string();
        let inputs = Array::new_with_length(2);
        inputs.set(0u32, wasm_bindgen::JsValue::from_str(&record_1.to_string()));
        inputs.set(1u32, wasm_bindgen::JsValue::from_str(&record_2.to_string()));

        let mut process_native = ProcessNative::load_web().map_err(|err| err.to_string())?;
        let process = &mut process_native;

        let stack = process.get_stack("credits.aleo").map_err(|e| e.to_string())?;
        let fee_identifier = if fee_record.is_some() {
            IdentifierNative::from_str("fee_private").map_err(|e| e.to_string())?
        } else {
            IdentifierNative::from_str("fee_public").map_err(|e| e.to_string())?
        };
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

        log("Executing the join function");
        let (_, mut trace) = execute_program!(
            process,
            process_inputs!(inputs),
            &program,
            "join",
            private_key,
            join_proving_key,
            join_verifying_key,
            rng
        );

        log("Preparing inclusion proof for the join execution");
        if let Some(offline_query) = offline_query.as_ref() {
            trace.prepare_async(offline_query.clone()).await.map_err(|err| err.to_string())?;
        } else {
            let query = QueryNative::from(node_url);
            trace.prepare_async(query).await.map_err(|err| err.to_string())?;
        }

        log("Proving the join execution");
        let execution = trace.prove_execution::<CurrentAleo, _>("credits.aleo/join", rng).map_err(|e| e.to_string())?;
        let execution_id = execution.to_execution_id().map_err(|e| e.to_string())?;

        log("Verifying the join execution");
        process.verify_execution(&execution).map_err(|err| err.to_string())?;

        // Get the storage cost in bytes for the program execution
        let storage_cost = execution.size_in_bytes().map_err(|e| e.to_string())?;

        let program = ProgramNative::from_str(&program).map_err(|err| err.to_string())?;
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
            priority_fee,
            node_url,
            fee_proving_key,
            fee_verifying_key,
            execution_id,
            rng,
            offline_query
        );

        log("Creating execution transaction for join");
        let transaction = TransactionNative::from_execution(execution, Some(fee)).map_err(|err| err.to_string())?;
        Ok(Transaction::from(transaction))
    }
    
    #[wasm_bindgen(js_name = buildJoinAuthorize)]
    #[allow(clippy::too_many_arguments)]
    pub async fn join_authorize(
        private_key: &PrivateKey,
        record_1: String,
        record_2: String,
        minimum_fee_cost: u64,
        priority_fee_in_microcredits: u64,
        fee_record: Option<String>,
        url: Option<String>,
        join_proving_key: Option<ProvingKey>,
        join_verifying_key: Option<VerifyingKey>,
        fee_proving_key: Option<ProvingKey>,
        fee_verifying_key: Option<VerifyingKey>,
    ) -> Result<String, String> {
        log("Authorize join program");
        let fee_record = match fee_record {
            Some(fee_record) => {
                Some(Self::parse_record(&private_key, fee_record).map_err(|_| "RecordCiphertext from_str".to_string())?)
            }
            None => None,
        };

        let priority_fee = match &fee_record {
            Some(fee_record) => Self::validate_amount(priority_fee_in_microcredits, fee_record, true)?,
            None => priority_fee_in_microcredits,
        };
        let rng = &mut StdRng::from_entropy();

        let record_1 = Self::parse_record(&private_key, record_1).map_err(|_| "RecordCiphertext from_str".to_string())?;
        let record_2 = Self::parse_record(&private_key, record_2).map_err(|_| "RecordCiphertext from_str".to_string())?;

        log("Setup program and inputs");
        let program = ProgramNative::credits().unwrap().to_string();
        let inputs = Array::new_with_length(2);
        inputs.set(0u32, wasm_bindgen::JsValue::from_str(&record_1.to_string()));
        inputs.set(1u32, wasm_bindgen::JsValue::from_str(&record_2.to_string()));

        let mut process_native = ProcessNative::load_web().map_err(|err| err.to_string())?;
        let process = &mut process_native;

        let stack = process.get_stack("credits.aleo").map_err(|e| e.to_string())?;
        let fee_identifier = if fee_record.is_some() {
            IdentifierNative::from_str("fee_private").map_err(|e| e.to_string())?
        } else {
            IdentifierNative::from_str("fee_public").map_err(|e| e.to_string())?
        };
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
        log("Authorizing join authorize");
        let authorize_program = authorize_program!(
            process,
            process_inputs!(inputs),
            &program,
            "join",
            private_key,
            join_proving_key,
            join_verifying_key,
            rng
        );

        log("Creating execution_id for execute program");
        let execution_id = *TransactionNative::transitions_tree(authorize_program.transitions().values(), &None)
            .map_err(|e| e.to_string())?
            .root();

        authorizations.push(Authorization::from(authorize_program));

        log("Authorizing the fee");
        let authorize_fee = authorize_fee!(
            process,
            private_key,
            fee_record,
            minimum_fee_cost,
            priority_fee,
            fee_proving_key,
            fee_verifying_key,
            execution_id,
            rng
        );

        authorizations.push(Authorization::from(authorize_fee));

        Ok(serde_json::to_string_pretty(&authorizations).unwrap_or_default())
    }
}
