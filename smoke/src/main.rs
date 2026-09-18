use std::{
    env,
    error::Error,
    fs,
    path::{Path, PathBuf},
};

use zylith_core::hash::ordered_felt_list_commitment;
use zylith_core::{
    AssetId, BatchId, ConsumedInput, ExecutionPreference, MatchedOrder, MatchedOrderWitness,
    MultiPairExecutableOrder, MultiPairNettingConfig, MultiPairObjectiveWeight, Note,
    OrderCommitment, OrderIntent, OrderSide, OrderType, OutputCiphertextBundle, OutputNoteRecord,
    OutputRecoveryRecord, PairId, RelayMode, SettlementTranscript, SettlementWitness, TimeInForce,
    build_admission_serialized_input, build_auction_result_serialized_input,
    build_multi_pair_serialized_input, build_multi_pair_settlement_serialized_input,
    build_multi_pair_settlement_witness, build_settlement_witness, build_stwo_serialized_input,
    deposit_root_from_note, encrypt_output_note_for_owner, note_accumulator_root_after_append,
    note_accumulator_root_after_deposits, note_recognition_public_key_from_raw_key_hex,
    nullifier_from_note_secret, nullifier_sparse_update_witnesses_for_consumed_inputs,
    output_note_merkle_proof, output_note_merkle_root, plan_multi_pair_netting,
    reference_price_attestation_commitment, reference_price_source_set_commitment,
    sign_order_authorization, sign_reference_price_attestation,
    spend_auth_key_felt_from_raw_key_hex, spend_authority_from_raw_key_hex,
    withdraw_authority_from_raw_key_hex,
};

fn main() -> Result<(), Box<dyn Error>> {
    let args = SmokeArgs::from_env()?;
    if let Some(witness_path) = args.settlement_witness_path.as_ref() {
        let witness: SettlementWitness = serde_json::from_slice(&fs::read(witness_path)?)?;
        let arguments = match args.statement {
            SmokeStatement::Settlement => build_stwo_serialized_input(&witness)?,
            SmokeStatement::Admission => build_admission_serialized_input(&witness, &[])?,
            SmokeStatement::AuctionResult => build_auction_result_serialized_input(&witness, &[])?,
            SmokeStatement::MultiPair => {
                return Err("--settlement-witness does not support multi-pair statements".into());
            }
            SmokeStatement::MultiPairSettlement => {
                return Err(
                    "--settlement-witness does not support multi-pair settlement statements".into(),
                );
            }
        };
        write_arguments(&args.output_path, &arguments)?;
        return Ok(());
    }

    let arguments = match args.scenario {
        SmokeScenario::Noop => build_smoke_arguments(args.statement)?,
        SmokeScenario::MultiPair => match args.statement {
            SmokeStatement::MultiPairSettlement => build_multi_pair_settlement_smoke_arguments()?,
            _ => build_multi_pair_smoke_arguments()?,
        },
    };
    write_arguments(&args.output_path, &arguments)?;
    if args.prover_data_dir.is_some() {
        return Err("--prover-data-dir is not supported by current smoke scenarios".into());
    }
    Ok(())
}

fn write_arguments(path: &Path, arguments: &[String]) -> Result<(), Box<dyn Error>> {
    let serialized = serde_json::to_string_pretty(arguments)?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, serialized)?;
    Ok(())
}

struct SmokeArgs {
    output_path: PathBuf,
    scenario: SmokeScenario,
    statement: SmokeStatement,
    prover_data_dir: Option<PathBuf>,
    settlement_witness_path: Option<PathBuf>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SmokeScenario {
    Noop,
    MultiPair,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SmokeStatement {
    Settlement,
    Admission,
    AuctionResult,
    MultiPair,
    MultiPairSettlement,
}

impl SmokeArgs {
    fn from_env() -> Result<Self, Box<dyn Error>> {
        let mut output_path = None;
        let mut scenario = SmokeScenario::Noop;
        let mut statement = SmokeStatement::Settlement;
        let mut prover_data_dir = None;
        let mut settlement_witness_path = None;
        let mut args = env::args().skip(1);
        while let Some(arg) = args.next() {
            match arg.as_str() {
                "--output" => {
                    output_path = Some(
                        args.next()
                            .map(PathBuf::from)
                            .ok_or("--output requires a path")?,
                    );
                }
                "--scenario" => {
                    let value = args.next().ok_or("--scenario requires a value")?;
                    scenario = match value.as_str() {
                        "noop" => SmokeScenario::Noop,
                        "multi-pair" => SmokeScenario::MultiPair,
                        _ => {
                            return Err("supported scenarios are: noop, multi-pair".into());
                        }
                    };
                }
                "--statement" => {
                    let value = args.next().ok_or("--statement requires a value")?;
                    statement = match value.as_str() {
                        "settlement" => SmokeStatement::Settlement,
                        "admission" => SmokeStatement::Admission,
                        "auction-result" => SmokeStatement::AuctionResult,
                        "multi-pair" => SmokeStatement::MultiPair,
                        "multi-pair-settlement" => SmokeStatement::MultiPairSettlement,
                        _ => {
                            return Err(
                                "supported statements are: settlement, admission, auction-result, multi-pair, multi-pair-settlement"
                                    .into(),
                            );
                        }
                    };
                }
                "--prover-data-dir" => {
                    prover_data_dir = Some(
                        args.next()
                            .map(PathBuf::from)
                            .ok_or("--prover-data-dir requires a path")?,
                    );
                }
                "--settlement-witness" => {
                    settlement_witness_path = Some(
                        args.next()
                            .map(PathBuf::from)
                            .ok_or("--settlement-witness requires a path")?,
                    );
                }
                _ => return Err(format!("unknown argument: {arg}").into()),
            }
        }
        Ok(Self {
            output_path: output_path.ok_or("usage: zylith-smoke --output <path>")?,
            scenario,
            statement,
            prover_data_dir,
            settlement_witness_path,
        })
    }
}

fn build_smoke_arguments(statement: SmokeStatement) -> Result<Vec<String>, Box<dyn Error>> {
    let batch_id = BatchId("stwo-smoke-batch-1".into());
    let order_commitment_root = ordered_felt_list_commitment("zylith/batch-order-root", &[])?;
    let output_bundle =
        OutputCiphertextBundle::from_ciphertexts(batch_id.clone(), "stwo-smoke-da", vec![])?;
    let output_recovery_dummy_commitments = output_bundle
        .ciphertexts
        .iter()
        .map(|ciphertext| {
            ciphertext
                .recovery
                .as_ref()
                .map(|recovery| recovery.commitment.clone())
                .ok_or("padded smoke ciphertext is missing its recovery commitment")
        })
        .collect::<Result<Vec<_>, _>>()?;

    let reference_attestation = smoke_reference_attestation(
        "0x999",
        PairId("STRK/USDC".into()),
        AssetId("STRK".into()),
        AssetId("USDC".into()),
        1,
        1_000_000_000_000_000_000,
        1,
    )?;
    let new_note_root = note_accumulator_root_after_append(
        &[],
        &output_note_merkle_root(&[], &output_bundle.bundle_commitment)?,
    )?;
    let transcript = SettlementTranscript {
        batch_id,
        pair_id: PairId("STRK/USDC".into()),
        batch_epoch: 1,
        auction_verifier_address: "0x999".into(),
        order_commitment_root,
        encrypted_order_set_commitment: "0x222".into(),
        reference_price_attestation_commitment: reference_price_attestation_commitment(
            &reference_attestation,
        )?,
        reference_price_signer: reference_attestation.signer_public_key.clone(),
        reference_price_observed_at_unix_ms: reference_attestation.envelope.observed_at_unix_ms,
        reference_price_valid_until_unix_ms: reference_attestation.valid_until_unix_ms,
        prior_note_root: "0x0".into(),
        prior_nullifier_root: "0x0".into(),
        prior_renewal_root: "0x0".into(),
        prior_fee_root: "0x0".into(),
        new_note_root,
        new_nullifier_root: "0x0".into(),
        new_renewal_root: "0x0".into(),
        clearing_price: 1,
        price_base_scale: 1_000_000_000_000_000_000,
        taker_fee_bps: 4,
        protocol_fee_recipient: "0x4010".into(),
        matched_orders: vec![],
        consumed_inputs: vec![],
        renewal_child_uses: vec![],
        fees: vec![],
        output_notes: vec![],
        output_note_preimages: vec![],
        output_recovery_records: vec![],
        output_recovery_dummy_commitments,
        output_ciphertext_bundle_ref: output_bundle.bundle_commitment,
        multi_pair_commitment: "0x0".into(),
    };
    let witness = build_settlement_witness(
        &transcript,
        transcript.pair_id.clone(),
        "0x999",
        AssetId("STRK".into()),
        AssetId("USDC".into()),
        vec![],
        reference_attestation,
    )?;

    match statement {
        SmokeStatement::Settlement => Ok(build_stwo_serialized_input(&witness)?),
        SmokeStatement::Admission => Ok(build_admission_serialized_input(&witness, &[])?),
        SmokeStatement::AuctionResult => Ok(build_auction_result_serialized_input(&witness, &[])?),
        SmokeStatement::MultiPair | SmokeStatement::MultiPairSettlement => Err(
            "noop scenario supports settlement, admission, and auction-result statements".into(),
        ),
    }
}

fn build_multi_pair_smoke_arguments() -> Result<Vec<String>, Box<dyn Error>> {
    let plan = plan_multi_pair_netting(
        BatchId("stwo-smoke-multi-pair-1".into()),
        &[
            multi_pair_executable_buy(MultiPairExecutableSpec {
                commitment: "0x101",
                pair: "ETH/USDC",
                base: "ETH",
                quote: "USDC",
                base_amount: 10,
                available_input_amount: 50_000,
                limit_price: 6_000,
            }),
            multi_pair_executable_sell(MultiPairExecutableSpec {
                commitment: "0x102",
                pair: "ETH/STRK",
                base: "ETH",
                quote: "STRK",
                base_amount: 10,
                available_input_amount: 10,
                limit_price: 5_000,
            }),
            multi_pair_executable_sell(MultiPairExecutableSpec {
                commitment: "0x103",
                pair: "STRK/USDC",
                base: "STRK",
                quote: "USDC",
                base_amount: 50_000,
                available_input_amount: 50_000,
                limit_price: 1,
            }),
        ],
        vec![
            MultiPairObjectiveWeight {
                asset_id: AssetId("ETH".into()),
                numerator: 5_000,
                denominator: 1,
            },
            MultiPairObjectiveWeight {
                asset_id: AssetId("USDC".into()),
                numerator: 1,
                denominator: 1,
            },
            MultiPairObjectiveWeight {
                asset_id: AssetId("STRK".into()),
                numerator: 1,
                denominator: 1,
            },
        ],
        MultiPairNettingConfig::default(),
    )?
    .ok_or("multi-pair smoke planner did not find a cycle")?;
    Ok(build_multi_pair_serialized_input(&plan.problem)?)
}

fn build_multi_pair_settlement_smoke_arguments() -> Result<Vec<String>, Box<dyn Error>> {
    let group_id = BatchId("stwo-smoke-multi-pair-settlement-1".into());
    let spend_key_felt = spend_auth_key_felt_from_raw_key_hex(&"22".repeat(32));
    let spend_authority = spend_authority_from_raw_key_hex(&"22".repeat(32))?;
    let output_owner_public_key = note_recognition_public_key_from_raw_key_hex(&"12".repeat(32))?;
    let output_spend_authority = spend_authority_from_raw_key_hex(&"23".repeat(32))?;
    let output_withdraw_authority = withdraw_authority_from_raw_key_hex(&"24".repeat(32))?;

    let funding_usdc = multi_pair_smoke_note(MultiPairSmokeNoteSpec {
        asset_id: AssetId("USDC".into()),
        amount: 2_000,
        owner_public_key: output_owner_public_key.clone(),
        spend_authority: spend_authority.clone(),
        withdraw_authority: output_withdraw_authority.clone(),
        blinding: "0x9101".into(),
        nonce: 9101,
        metadata_commitment: "0xa101".into(),
    });
    let funding_eth = multi_pair_smoke_note(MultiPairSmokeNoteSpec {
        asset_id: AssetId("ETH".into()),
        amount: 1,
        owner_public_key: output_owner_public_key.clone(),
        spend_authority: spend_authority.clone(),
        withdraw_authority: output_withdraw_authority.clone(),
        blinding: "0x9102".into(),
        nonce: 9102,
        metadata_commitment: "0xa102".into(),
    });
    let funding_strk = multi_pair_smoke_note(MultiPairSmokeNoteSpec {
        asset_id: AssetId("STRK".into()),
        amount: 100,
        owner_public_key: output_owner_public_key.clone(),
        spend_authority: spend_authority.clone(),
        withdraw_authority: output_withdraw_authority.clone(),
        blinding: "0x9103".into(),
        nonce: 9103,
        metadata_commitment: "0xa103".into(),
    });
    let output_eth = multi_pair_smoke_note(MultiPairSmokeNoteSpec {
        asset_id: AssetId("ETH".into()),
        amount: 1,
        owner_public_key: output_owner_public_key.clone(),
        spend_authority: output_spend_authority.clone(),
        withdraw_authority: output_withdraw_authority.clone(),
        blinding: "0x9201".into(),
        nonce: 9201,
        metadata_commitment: "0xa201".into(),
    });
    let output_strk = multi_pair_smoke_note(MultiPairSmokeNoteSpec {
        asset_id: AssetId("STRK".into()),
        amount: 100,
        owner_public_key: output_owner_public_key.clone(),
        spend_authority: output_spend_authority.clone(),
        withdraw_authority: output_withdraw_authority.clone(),
        blinding: "0x9202".into(),
        nonce: 9202,
        metadata_commitment: "0xa202".into(),
    });
    let output_usdc = multi_pair_smoke_note(MultiPairSmokeNoteSpec {
        asset_id: AssetId("USDC".into()),
        amount: 2_000,
        owner_public_key: output_owner_public_key,
        spend_authority: output_spend_authority,
        withdraw_authority: output_withdraw_authority,
        blinding: "0x9203".into(),
        nonce: 9203,
        metadata_commitment: "0xa203".into(),
    });
    let order_a_commitment = multi_pair_smoke_order_commitment(MultiPairSmokeOrderSpec {
        pair: "ETH/USDC",
        batch: "batch-eth-usdc-99",
        side: OrderSide::Buy,
        limit_price: 2_000,
        amount: 1,
        min_fill: 1,
        expiry_epoch: 99,
        order_nonce: 991,
        funding_note: funding_usdc.clone(),
        output_note: output_eth.clone(),
    })?;
    let order_b_commitment = multi_pair_smoke_order_commitment(MultiPairSmokeOrderSpec {
        pair: "ETH/STRK",
        batch: "batch-eth-strk-99",
        side: OrderSide::Sell,
        limit_price: 100,
        amount: 1,
        min_fill: 1,
        expiry_epoch: 99,
        order_nonce: 992,
        funding_note: funding_eth.clone(),
        output_note: output_strk.clone(),
    })?;
    let order_c_commitment = multi_pair_smoke_order_commitment(MultiPairSmokeOrderSpec {
        pair: "STRK/USDC",
        batch: "batch-strk-usdc-99",
        side: OrderSide::Sell,
        limit_price: 20,
        amount: 100,
        min_fill: 1,
        expiry_epoch: 99,
        order_nonce: 993,
        funding_note: funding_strk.clone(),
        output_note: output_usdc.clone(),
    })?;
    let order_a = multi_pair_executable_buy(MultiPairExecutableSpec {
        commitment: &order_a_commitment.0,
        pair: "ETH/USDC",
        base: "ETH",
        quote: "USDC",
        base_amount: 1,
        available_input_amount: 2_000,
        limit_price: 2_000,
    });
    let order_b = multi_pair_executable_sell(MultiPairExecutableSpec {
        commitment: &order_b_commitment.0,
        pair: "ETH/STRK",
        base: "ETH",
        quote: "STRK",
        base_amount: 1,
        available_input_amount: 1,
        limit_price: 100,
    });
    let order_c = multi_pair_executable_sell(MultiPairExecutableSpec {
        commitment: &order_c_commitment.0,
        pair: "STRK/USDC",
        base: "STRK",
        quote: "USDC",
        base_amount: 100,
        available_input_amount: 100,
        limit_price: 20,
    });
    let plan = plan_multi_pair_netting(
        group_id.clone(),
        &[order_a.clone(), order_b.clone(), order_c.clone()],
        vec![
            MultiPairObjectiveWeight {
                asset_id: AssetId("USDC".into()),
                numerator: 1,
                denominator: 1,
            },
            MultiPairObjectiveWeight {
                asset_id: AssetId("ETH".into()),
                numerator: 2_000,
                denominator: 1,
            },
            MultiPairObjectiveWeight {
                asset_id: AssetId("STRK".into()),
                numerator: 20,
                denominator: 1,
            },
        ],
        MultiPairNettingConfig::default(),
    )?
    .ok_or("multi-pair settlement smoke planner did not find a cycle")?;
    let problem = plan.problem;
    let multi_pair_commitment = zylith_core::multi_pair_statement_commitment(&problem)?;
    let order_a_commitment_hex = order_a_commitment.0.clone();
    let order_b_commitment_hex = order_b_commitment.0.clone();
    let order_c_commitment_hex = order_c_commitment.0.clone();
    let funding_notes = problem
        .chosen
        .fills
        .iter()
        .map(|fill| match fill.order_commitment.0.as_str() {
            commitment if commitment == order_a_commitment_hex => Ok(funding_usdc.clone()),
            commitment if commitment == order_b_commitment_hex => Ok(funding_eth.clone()),
            commitment if commitment == order_c_commitment_hex => Ok(funding_strk.clone()),
            _ => Err("unexpected multi-pair smoke fill commitment".into()),
        })
        .collect::<Result<Vec<_>, Box<dyn Error>>>()?;
    let consumed_inputs = funding_notes
        .iter()
        .map(|note| {
            let commitment = note.commitment()?;
            let nullifier = nullifier_from_note_secret(&commitment, &note.blinding)?;
            Ok(ConsumedInput {
                note_commitment: commitment,
                nullifier,
            })
        })
        .collect::<Result<Vec<_>, zylith_core::ProtocolError>>()?;
    let deposit_roots = funding_notes
        .iter()
        .map(deposit_root_from_note)
        .collect::<Result<Vec<_>, _>>()?;
    let prior_note_root = note_accumulator_root_after_deposits(&deposit_roots)?;
    let (_, new_nullifier_root, _) =
        nullifier_sparse_update_witnesses_for_consumed_inputs(&[], &consumed_inputs)?;
    let output_note_preimages = problem
        .chosen
        .fills
        .iter()
        .map(|fill| match fill.order_commitment.0.as_str() {
            commitment if commitment == order_a_commitment_hex => Ok(output_eth.clone()),
            commitment if commitment == order_b_commitment_hex => Ok(output_strk.clone()),
            commitment if commitment == order_c_commitment_hex => Ok(output_usdc.clone()),
            _ => Err("unexpected multi-pair smoke fill commitment".into()),
        })
        .collect::<Result<Vec<_>, Box<dyn Error>>>()?;
    let (output_bundle, output_notes, output_recovery_records, output_recovery_dummy_commitments) =
        output_bundle_for_notes(
            group_id.clone(),
            "stwo-smoke-multi-pair-settlement-da",
            &output_note_preimages,
        )?;

    let output_note_root =
        output_note_merkle_root(&output_notes, &output_bundle.bundle_commitment)?;
    let new_note_root = note_accumulator_root_after_append(&deposit_roots, &output_note_root)?;
    let mut transcript = zylith_core::MultiPairSettlementTranscript {
        group_id: group_id.clone(),
        batch_epoch: 99,
        auction_verifier_address: "0x999".into(),
        batch_bindings: vec![
            zylith_core::MultiPairSettlementBatchBinding {
                batch_id: BatchId("batch-eth-usdc-99".into()),
                pair_id: PairId("ETH/USDC".into()),
                batch_epoch: 99,
                order_commitment_root: "0x3111".into(),
                admission_root: "0x4111".into(),
                encrypted_order_set_commitment: "0x3211".into(),
                reference_price_attestation_commitment: "0x1".into(),
                reference_price_signer: "0x1".into(),
                reference_price_observed_at_unix_ms: 1_000,
                reference_price_valid_until_unix_ms: 6_000,
                base_asset_id: AssetId("ETH".into()),
                quote_asset_id: AssetId("USDC".into()),
                price_base_scale: 1,
                taker_fee_bps: 0,
            },
            zylith_core::MultiPairSettlementBatchBinding {
                batch_id: BatchId("batch-eth-strk-99".into()),
                pair_id: PairId("ETH/STRK".into()),
                batch_epoch: 99,
                order_commitment_root: "0x3112".into(),
                admission_root: "0x4112".into(),
                encrypted_order_set_commitment: "0x3212".into(),
                reference_price_attestation_commitment: "0x1".into(),
                reference_price_signer: "0x1".into(),
                reference_price_observed_at_unix_ms: 1_000,
                reference_price_valid_until_unix_ms: 6_000,
                base_asset_id: AssetId("ETH".into()),
                quote_asset_id: AssetId("STRK".into()),
                price_base_scale: 1,
                taker_fee_bps: 0,
            },
            zylith_core::MultiPairSettlementBatchBinding {
                batch_id: BatchId("batch-strk-usdc-99".into()),
                pair_id: PairId("STRK/USDC".into()),
                batch_epoch: 99,
                order_commitment_root: "0x3113".into(),
                admission_root: "0x4113".into(),
                encrypted_order_set_commitment: "0x3213".into(),
                reference_price_attestation_commitment: "0x1".into(),
                reference_price_signer: "0x1".into(),
                reference_price_observed_at_unix_ms: 1_000,
                reference_price_valid_until_unix_ms: 6_000,
                base_asset_id: AssetId("STRK".into()),
                quote_asset_id: AssetId("USDC".into()),
                price_base_scale: 1,
                taker_fee_bps: 0,
            },
        ],
        prior_note_root,
        prior_nullifier_root: "0x0".into(),
        prior_renewal_root: "0x0".into(),
        prior_fee_root: "0x0".into(),
        new_note_root,
        new_nullifier_root,
        new_renewal_root: "0x0".into(),
        protocol_fee_recipient: "0x4010".into(),
        multi_pair_commitment,
        external_match_settlements: vec![],
        matched_orders: problem
            .chosen
            .fills
            .iter()
            .map(|fill| MatchedOrder {
                order_commitment: fill.order_commitment.clone(),
                filled_amount: fill.filled_base_amount,
            })
            .collect(),
        consumed_inputs,
        renewal_child_uses: vec![],
        fees: vec![],
        output_notes,
        output_note_preimages,
        output_recovery_records,
        output_recovery_dummy_commitments,
        output_ciphertext_bundle_ref: output_bundle.bundle_commitment,
    };
    let matched_order_witnesses = problem
        .chosen
        .fills
        .iter()
        .map(|fill| {
            let (batch_id, funding_note, output_note, order_nonce) =
                match fill.order_commitment.0.as_str() {
                    commitment if commitment == order_a_commitment_hex => (
                        BatchId("batch-eth-usdc-99".into()),
                        funding_usdc.clone(),
                        output_eth.clone(),
                        991,
                    ),
                    commitment if commitment == order_b_commitment_hex => (
                        BatchId("batch-eth-strk-99".into()),
                        funding_eth.clone(),
                        output_strk.clone(),
                        992,
                    ),
                    commitment if commitment == order_c_commitment_hex => (
                        BatchId("batch-strk-usdc-99".into()),
                        funding_strk.clone(),
                        output_usdc.clone(),
                        993,
                    ),
                    _ => return Err("unexpected multi-pair smoke fill commitment".into()),
                };
            let funding_note_ref = funding_note.commitment()?;
            let funding_nullifier =
                nullifier_from_note_secret(&funding_note_ref, &funding_note.blinding)?;
            Ok(zylith_core::MultiPairMatchedOrderWitness {
                batch_id,
                fill: fill.clone(),
                order_witness: MatchedOrderWitness {
                    order_commitment: fill.order_commitment.clone(),
                    funding_note: funding_note.clone(),
                    funding_notes: vec![funding_note],
                    funding_note_ref,
                    funding_nullifier: funding_nullifier.clone(),
                    funding_nullifiers: vec![funding_nullifier],
                    funding_authorization: sign_order_authorization(
                        &spend_key_felt,
                        &fill.order_commitment,
                    )?,
                    side: fill.side,
                    order_type: OrderType::LimitBatch,
                    relay_mode: RelayMode::SelfRelay,
                    limit_price: fill.limit_price,
                    order_amount: fill.submitted_base_amount,
                    min_fill: fill.min_fill_base_amount,
                    time_in_force: TimeInForce::CurrentBatchOnly,
                    execution_preference: ExecutionPreference::PrivateThenExternal,
                    expiry_epoch: 99,
                    order_nonce,
                    parent_order_commitment: "0x0".into(),
                    parent_child_index: 0,
                    parent_secret_commitment: "0x0".into(),
                    parent_cancel_authority: "0x0".into(),
                    parent_authorization_secret: "0x0".into(),
                    auditor_view_allowed: false,
                    recipient_owner_public_key: output_note.owner_public_key.clone(),
                    recipient_spend_authority: output_note.spend_authority.clone(),
                    recipient_withdraw_authority: output_note.withdraw_authority.clone(),
                    recipient_residual_withdraw_authority: output_note.withdraw_authority.clone(),
                    filled_amount: fill.filled_base_amount,
                    output_note,
                    residual_note: None,
                },
            })
        })
        .collect::<Result<Vec<_>, Box<dyn Error>>>()?;
    let admission_order_summaries = matched_order_witnesses
        .iter()
        .map(|entry| zylith_core::MultiPairAdmissionOrderSummary {
            batch_id: entry.batch_id.clone(),
            order_commitment: entry.order_witness.order_commitment.clone(),
            side: entry.order_witness.side,
            order_type: entry.order_witness.order_type,
            relay_mode: entry.order_witness.relay_mode.clone(),
            limit_price: entry.order_witness.limit_price,
            order_amount: entry.order_witness.order_amount,
            min_fill: entry.order_witness.min_fill,
            time_in_force: entry.order_witness.time_in_force,
            execution_preference: entry.order_witness.execution_preference,
            funding_note_amount: entry
                .order_witness
                .effective_funding_notes()
                .iter()
                .map(|note| note.amount)
                .sum(),
            funding_note_owner_public_key: entry
                .order_witness
                .funding_note
                .owner_public_key
                .clone(),
        })
        .collect::<Vec<_>>();
    for binding in &mut transcript.batch_bindings {
        let summaries = admission_order_summaries
            .iter()
            .filter(|summary| summary.batch_id == binding.batch_id)
            .cloned()
            .collect::<Vec<_>>();
        binding.order_commitment_root = zylith_core::hash::ordered_felt_list_commitment(
            "zylith/batch-order-root",
            &summaries
                .iter()
                .map(|summary| summary.order_commitment.0.clone())
                .collect::<Vec<_>>(),
        )?;
        binding.admission_root = zylith_core::multi_pair_admission_root_from_summaries(&summaries)?;
    }
    let reference_price_attestations = transcript
        .batch_bindings
        .iter_mut()
        .enumerate()
        .map(|(index, binding)| {
            let midpoint_price = match binding.pair_id.0.as_str() {
                "ETH/USDC" => 2_000,
                "ETH/STRK" => 100,
                "STRK/USDC" => 20,
                _ => return Err("unexpected multi-pair smoke reference pair".into()),
            };
            let attestation = smoke_reference_attestation(
                "0x999",
                binding.pair_id.clone(),
                binding.base_asset_id.clone(),
                binding.quote_asset_id.clone(),
                midpoint_price,
                binding.price_base_scale,
                index as u64 + 1,
            )?;
            binding.reference_price_attestation_commitment =
                reference_price_attestation_commitment(&attestation)?;
            binding.reference_price_signer = attestation.signer_public_key.clone();
            binding.reference_price_observed_at_unix_ms = attestation.envelope.observed_at_unix_ms;
            binding.reference_price_valid_until_unix_ms = attestation.valid_until_unix_ms;
            Ok(attestation)
        })
        .collect::<Result<Vec<_>, Box<dyn Error>>>()?;
    let witness = build_multi_pair_settlement_witness(
        &transcript,
        "0x999",
        problem,
        matched_order_witnesses,
        admission_order_summaries,
        reference_price_attestations,
    )?;
    Ok(build_multi_pair_settlement_serialized_input(&witness)?)
}

fn smoke_reference_attestation(
    verifier_address: &str,
    pair_id: PairId,
    base_asset_id: AssetId,
    quote_asset_id: AssetId,
    midpoint_price: u128,
    price_base_scale: u128,
    nonce: u64,
) -> Result<zylith_core::ReferencePriceAttestation, Box<dyn Error>> {
    let observed_at_unix_ms = 1_000;
    let source_set_commitment = reference_price_source_set_commitment(&[
        ("binance", midpoint_price),
        ("coinbase", midpoint_price),
        ("kraken", midpoint_price),
    ])?;
    Ok(sign_reference_price_attestation(
        "0x12345",
        verifier_address,
        zylith_core::ReferencePriceEnvelope {
            pair_id,
            base_asset_id,
            quote_asset_id,
            midpoint_price,
            lower_price: midpoint_price,
            upper_price: midpoint_price,
            price_base_scale,
            source_count: 3,
            observed_at_unix_ms,
        },
        &source_set_commitment,
        observed_at_unix_ms + 5_000,
        nonce,
    )?)
}

type OutputBundleParts = (
    OutputCiphertextBundle,
    Vec<OutputNoteRecord>,
    Vec<OutputRecoveryRecord>,
    Vec<String>,
);

fn output_bundle_for_notes(
    batch_id: BatchId,
    data_availability_ref: &str,
    notes: &[Note],
) -> Result<OutputBundleParts, Box<dyn Error>> {
    let output_notes = notes
        .iter()
        .map(output_record_from_note)
        .collect::<Result<Vec<_>, _>>()?;
    let ciphertexts = notes
        .iter()
        .enumerate()
        .map(|(index, note)| {
            let proof =
                output_note_merkle_proof(&output_notes, &output_notes[index].note_commitment)?;
            encrypt_output_note_for_owner(
                &batch_id.0,
                index,
                note,
                &output_notes[index],
                &proof,
                &note.owner_public_key,
            )
        })
        .collect::<Result<Vec<_>, _>>()?;
    let output_recovery_records = ciphertexts
        .iter()
        .map(|ciphertext| {
            ciphertext
                .recovery
                .clone()
                .ok_or("output ciphertext is missing its recovery commitment")
        })
        .collect::<Result<Vec<_>, _>>()?;
    let output_bundle =
        OutputCiphertextBundle::from_ciphertexts(batch_id, data_availability_ref, ciphertexts)?;
    let output_recovery_dummy_commitments = output_bundle
        .ciphertexts
        .iter()
        .skip(notes.len())
        .map(|ciphertext| {
            ciphertext
                .recovery
                .as_ref()
                .map(|recovery| recovery.commitment.clone())
                .ok_or("padded lifecycle ciphertext is missing its recovery commitment")
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok((
        output_bundle,
        output_notes,
        output_recovery_records,
        output_recovery_dummy_commitments,
    ))
}

fn output_record_from_note(note: &Note) -> Result<OutputNoteRecord, zylith_core::ProtocolError> {
    Ok(OutputNoteRecord {
        note_commitment: note.commitment()?,
        asset_id: note.asset_id.clone(),
        amount: note.amount,
        withdraw_authority: note.withdraw_authority.clone(),
    })
}

struct MultiPairExecutableSpec<'a> {
    commitment: &'a str,
    pair: &'a str,
    base: &'a str,
    quote: &'a str,
    base_amount: u128,
    available_input_amount: u128,
    limit_price: u128,
}

struct MultiPairSmokeNoteSpec {
    asset_id: AssetId,
    amount: u128,
    owner_public_key: String,
    spend_authority: String,
    withdraw_authority: String,
    blinding: String,
    nonce: u64,
    metadata_commitment: String,
}

struct MultiPairSmokeOrderSpec {
    pair: &'static str,
    batch: &'static str,
    side: OrderSide,
    limit_price: u128,
    amount: u128,
    min_fill: u128,
    expiry_epoch: u64,
    order_nonce: u64,
    funding_note: Note,
    output_note: Note,
}

fn multi_pair_smoke_note(spec: MultiPairSmokeNoteSpec) -> Note {
    Note {
        asset_id: spec.asset_id,
        amount: spec.amount,
        owner_public_key: spec.owner_public_key,
        spend_authority: spec.spend_authority,
        withdraw_authority: spec.withdraw_authority,
        blinding: spec.blinding,
        nonce: spec.nonce,
        metadata_commitment: spec.metadata_commitment,
    }
}

fn multi_pair_smoke_order_commitment(
    spec: MultiPairSmokeOrderSpec,
) -> Result<OrderCommitment, zylith_core::ProtocolError> {
    let funding_note_ref = spec.funding_note.commitment()?;
    let funding_nullifier =
        nullifier_from_note_secret(&funding_note_ref, &spec.funding_note.blinding)?;
    OrderIntent {
        pair_id: PairId(spec.pair.into()),
        batch_id: BatchId(spec.batch.into()),
        side: spec.side,
        order_type: OrderType::LimitBatch,
        relay_mode: RelayMode::SelfRelay,
        limit_price: spec.limit_price,
        amount: spec.amount,
        min_fill: spec.min_fill,
        time_in_force: TimeInForce::CurrentBatchOnly,
        execution_preference: ExecutionPreference::PrivateThenExternal,
        expiry_epoch: spec.expiry_epoch,
        order_nonce: spec.order_nonce,
        parent_order_commitment: "0x0".into(),
        parent_child_index: 0,
        parent_secret_commitment: "0x0".into(),
        parent_cancel_authority: "0x0".into(),
        parent_authorization_secret: "0x0".into(),
        funding_note_ref,
        funding_nullifier,
        recipient_owner_public_key: spec.output_note.owner_public_key,
        recipient_spend_authority: spec.output_note.spend_authority,
        recipient_withdraw_authority: spec.output_note.withdraw_authority.clone(),
        recipient_residual_withdraw_authority: spec.output_note.withdraw_authority,
        auditor_view_allowed: false,
    }
    .commitment()
}

fn multi_pair_executable_buy(spec: MultiPairExecutableSpec<'_>) -> MultiPairExecutableOrder {
    multi_pair_executable(spec, OrderSide::Buy)
}

fn multi_pair_executable_sell(spec: MultiPairExecutableSpec<'_>) -> MultiPairExecutableOrder {
    multi_pair_executable(spec, OrderSide::Sell)
}

fn multi_pair_executable(
    spec: MultiPairExecutableSpec<'_>,
    side: OrderSide,
) -> MultiPairExecutableOrder {
    MultiPairExecutableOrder {
        order_commitment: OrderCommitment(spec.commitment.into()),
        pair_id: PairId(spec.pair.into()),
        base_asset_id: AssetId(spec.base.into()),
        quote_asset_id: AssetId(spec.quote.into()),
        side,
        submitted_base_amount: spec.base_amount,
        min_fill_base_amount: 1,
        limit_price: spec.limit_price,
        price_base_scale: 1,
        available_input_amount: spec.available_input_amount,
        taker_fee_bps: 0,
        execution_preference: ExecutionPreference::PrivateThenExternal,
    }
}

#[cfg(test)]
mod tests {
    use super::{
        SmokeStatement, build_multi_pair_settlement_smoke_arguments,
        build_multi_pair_smoke_arguments, build_smoke_arguments,
    };

    #[test]
    fn smoke_arguments_are_a_single_length_prefixed_settlement_span() {
        let arguments = build_smoke_arguments(SmokeStatement::Settlement).expect("smoke arguments");
        let payload_len = usize::from_str_radix(arguments[0].trim_start_matches("0x"), 16)
            .expect("payload length");
        assert_eq!(payload_len, arguments.len() - 1);
        assert_eq!(arguments[1], "0x1");
    }

    #[test]
    fn split_noop_smoke_arguments_use_requested_statement_tag() {
        let admission =
            build_smoke_arguments(SmokeStatement::Admission).expect("admission smoke arguments");
        let auction_result = build_smoke_arguments(SmokeStatement::AuctionResult)
            .expect("auction result smoke arguments");

        assert_eq!(admission[1], "0x3");
        assert_eq!(auction_result[1], "0x4");
    }

    #[test]
    fn multi_pair_smoke_arguments_are_a_single_length_prefixed_span() {
        let arguments = build_multi_pair_smoke_arguments().expect("multi-pair smoke arguments");
        let payload_len = usize::from_str_radix(arguments[0].trim_start_matches("0x"), 16)
            .expect("payload length");
        assert_eq!(payload_len, arguments.len() - 1);
        assert_eq!(arguments[1], "0x8");
    }

    #[test]
    fn multi_pair_settlement_smoke_arguments_are_a_single_length_prefixed_span() {
        let arguments = build_multi_pair_settlement_smoke_arguments()
            .expect("multi-pair settlement smoke arguments");
        let payload_len = usize::from_str_radix(arguments[0].trim_start_matches("0x"), 16)
            .expect("payload length");
        assert_eq!(payload_len, arguments.len() - 1);
        assert_eq!(arguments[1], "0x9");
    }
}
