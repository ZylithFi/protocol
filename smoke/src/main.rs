use std::{
    env,
    error::Error,
    fs,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use zylith_core::hash::ordered_felt_list_commitment;
use zylith_core::{
    AssetId, AuctionOrderWitness, BatchId, BatchStatus, BatchSummary, ConsumedInput,
    LIQUIDITY_POSITION_VERSION, LiquidityPositionBacking, LiquidityPositionCurveKind,
    LiquidityPositionCurvePolicy, LiquidityPositionMarketContext, LiquidityPositionOpenFunding,
    LiquidityPositionOracleGuard, LiquidityPositionRootTransition, LiquidityPositionRotationPolicy,
    LiquidityPositionSettlementFill, LiquidityPositionState, LiquidityPositionStatus,
    LiquidityPositionTransitionKind, LiquidityPositionTransitionWitness, MatchedOrder,
    MatchedOrderWitness, MultiPairAssetDelta, MultiPairAssetDeltaDirection,
    MultiPairAssetDeltaSource, MultiPairCandidateSolution, MultiPairFeasibilityProblem,
    MultiPairFill, MultiPairObjectiveWeight, MultiPairOptimalityProblem, Note, OrderCommitment,
    OrderIntent, OrderSide, OrderType, OutputCiphertextBundle, OutputNoteRecord,
    OutputRecoveryRecord, PairId, PrivateLiquidityPosition, PublishedBatchArtifacts, RelayMode,
    SettlementTranscript, SettlementWitness, TimeInForce, apply_liquidity_position_fill,
    auction_admission_root, build_admission_serialized_input,
    build_auction_result_serialized_input, build_heartbeat_cover_orders,
    build_liquidity_position_serialized_input, build_multi_pair_serialized_input,
    build_settlement_witness, build_stwo_serialized_input, close_liquidity_position,
    deposit_root_from_note, encrypt_output_note_for_owner, encrypted_note_activation_commitment,
    funding_commitment_for_deposit, funding_input_set_commitment, funding_nullifier_set_commitment,
    heartbeat_cover_order_count, liquidity_position_private_authority,
    liquidity_position_root_transition, note_recognition_public_key_from_raw_key_hex,
    nullifier_from_note_secret, nullifier_sparse_update_witnesses_for_consumed_inputs,
    output_note_merkle_proof, quote_amount_for_base_amount,
    settlement_note_root_after_deposit_roots, settlement_transcript_commitment,
    sign_liquidity_position_transition, sign_order_authorization,
    spend_auth_key_felt_from_raw_key_hex, spend_authority_from_raw_key_hex,
    withdraw_authority_from_raw_key_hex,
};

const PRICE_SCALE_18: u128 = 1_000_000_000_000_000_000;
const USDC_SCALE_6: u128 = 1_000_000;

fn main() -> Result<(), Box<dyn Error>> {
    let args = SmokeArgs::from_env()?;
    if let Some(witness_path) = args.settlement_witness_path.as_ref() {
        let witness: SettlementWitness = serde_json::from_slice(&fs::read(witness_path)?)?;
        let arguments = match args.statement {
            SmokeStatement::Settlement => build_stwo_serialized_input(&witness)?,
            SmokeStatement::Admission => build_admission_serialized_input(&witness, &[])?,
            SmokeStatement::AuctionResult => build_auction_result_serialized_input(&witness, &[])?,
            SmokeStatement::LiquidityPosition => {
                build_liquidity_position_serialized_input(&witness)?
            }
            SmokeStatement::MultiPair => {
                return Err("--settlement-witness does not support multi-pair statements".into());
            }
        };
        write_arguments(&args.output_path, &arguments)?;
        return Ok(());
    }

    let fixture = if matches!(
        args.scenario,
        SmokeScenario::LpOpenFillE2e | SmokeScenario::LpOpenFillAuctionResult
    ) {
        Some(build_lp_open_fill_e2e_smoke_fixture()?)
    } else {
        None
    };
    let arguments = if let Some(fixture) = fixture.as_ref() {
        arguments_for_fixture(fixture, args.statement)?
    } else {
        match args.scenario {
            SmokeScenario::Noop => build_smoke_arguments()?,
            SmokeScenario::LpFill => build_lp_fill_smoke_arguments()?,
            SmokeScenario::LpUserFillAuctionResult => {
                build_lp_user_fill_auction_result_smoke_arguments()?
            }
            SmokeScenario::LpSoak => build_lp_soak_smoke_arguments()?,
            SmokeScenario::LpLifecycle => build_lp_lifecycle_smoke_arguments()?,
            SmokeScenario::LpOpenFillE2e | SmokeScenario::LpOpenFillAuctionResult => {
                unreachable!("LP E2E fixture should be built once")
            }
            SmokeScenario::LpOracleSkew => build_lp_oracle_skew_smoke_arguments()?,
            SmokeScenario::MultiPair => build_multi_pair_smoke_arguments()?,
        }
    };
    write_arguments(&args.output_path, &arguments)?;
    if let Some(prover_data_dir) = args.prover_data_dir {
        let fixture = fixture.as_ref().ok_or(
            "--prover-data-dir is currently supported only with --scenario lp-open-fill-e2e",
        )?;
        write_prover_data_dir(&prover_data_dir, fixture)?;
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
    LpFill,
    LpUserFillAuctionResult,
    LpSoak,
    LpLifecycle,
    LpOpenFillE2e,
    LpOpenFillAuctionResult,
    LpOracleSkew,
    MultiPair,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SmokeStatement {
    Settlement,
    Admission,
    AuctionResult,
    LiquidityPosition,
    MultiPair,
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
                        "lp-fill" => SmokeScenario::LpFill,
                        "lp-user-fill-auction-result" => SmokeScenario::LpUserFillAuctionResult,
                        "lp-soak" => SmokeScenario::LpSoak,
                        "lp-lifecycle" => SmokeScenario::LpLifecycle,
                        "lp-open-fill-e2e" => SmokeScenario::LpOpenFillE2e,
                        "lp-open-fill-auction-result" => SmokeScenario::LpOpenFillAuctionResult,
                        "lp-oracle-skew" => SmokeScenario::LpOracleSkew,
                        "multi-pair" => SmokeScenario::MultiPair,
                        _ => {
                            return Err(
                                "supported scenarios are: noop, lp-fill, lp-user-fill-auction-result, lp-soak, lp-lifecycle, lp-open-fill-e2e, lp-open-fill-auction-result, lp-oracle-skew, multi-pair"
                                    .into(),
                            );
                        }
                    };
                }
                "--statement" => {
                    let value = args.next().ok_or("--statement requires a value")?;
                    statement = match value.as_str() {
                        "settlement" => SmokeStatement::Settlement,
                        "admission" => SmokeStatement::Admission,
                        "auction-result" => SmokeStatement::AuctionResult,
                        "liquidity-position" => SmokeStatement::LiquidityPosition,
                        "multi-pair" => SmokeStatement::MultiPair,
                        _ => {
                            return Err(
                                "supported statements are: settlement, admission, auction-result, liquidity-position, multi-pair"
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

struct SmokeFixture {
    arguments: Vec<String>,
    auction_result_arguments: Option<Vec<String>>,
    auction_order_witnesses: Vec<AuctionOrderWitness>,
    published_artifacts: PublishedBatchArtifacts,
    funding_activations: Vec<SmokeFundingActivation>,
    admission_root: Option<String>,
}

struct SmokeFundingActivation {
    funding_commitment: String,
    deposit_root: String,
    encrypted_note_activation: String,
    note_commitment: String,
}

fn arguments_for_fixture(
    fixture: &SmokeFixture,
    statement: SmokeStatement,
) -> Result<Vec<String>, Box<dyn Error>> {
    match statement {
        SmokeStatement::Settlement => Ok(fixture.arguments.clone()),
        SmokeStatement::Admission => build_admission_serialized_input(
            &fixture.published_artifacts.settlement_witness,
            &fixture.auction_order_witnesses,
        )
        .map_err(Into::into),
        SmokeStatement::AuctionResult => fixture
            .auction_result_arguments
            .clone()
            .ok_or_else(|| "fixture is missing auction-result arguments".into()),
        SmokeStatement::LiquidityPosition => build_liquidity_position_serialized_input(
            &fixture.published_artifacts.settlement_witness,
        )
        .map_err(Into::into),
        SmokeStatement::MultiPair => build_multi_pair_smoke_arguments(),
    }
}

struct SmokeSettlementFeeConfig {
    taker_fee_bps: u16,
    relay_fee_bps: u16,
    protocol_fee_recipient: String,
    relay_fee_recipient: String,
}

fn write_prover_data_dir(path: &Path, fixture: &SmokeFixture) -> Result<(), Box<dyn Error>> {
    let batch_id = &fixture.published_artifacts.transcript.batch_id.0;
    fs::create_dir_all(path.join("prepared_batch_artifacts"))?;
    fs::create_dir_all(path.join("settlement_witnesses"))?;
    fs::create_dir_all(path.join("e2e"))?;
    let storage_key = storage_key(batch_id);
    fs::write(
        path.join("prepared_batch_artifacts")
            .join(format!("{storage_key}.json")),
        serde_json::to_string_pretty(&fixture.published_artifacts)?,
    )?;
    fs::write(
        path.join("settlement_witnesses")
            .join(format!("{storage_key}.json")),
        serde_json::to_string_pretty(&fixture.published_artifacts.settlement_witness)?,
    )?;
    let activations = fixture
        .funding_activations
        .iter()
        .map(|activation| {
            serde_json::json!({
                "funding_commitment": activation.funding_commitment,
                "deposit_root": activation.deposit_root,
                "encrypted_note_activation": activation.encrypted_note_activation,
                "note_commitment": activation.note_commitment,
            })
        })
        .collect::<Vec<_>>();
    let manifest = serde_json::json!({
        "batch_id": batch_id,
        "scenario": "lp-open-fill-e2e",
        "settlement_input_len": fixture.arguments.len(),
        "order_commitment_root": fixture.published_artifacts.transcript.order_commitment_root,
        "transcript_commitment": settlement_transcript_commitment(
            &fixture.published_artifacts.transcript,
        )?,
        "admission_root": fixture.admission_root,
        "funding_activations": activations,
        "created_at_unix_ms": now_unix_ms(),
    });
    fs::write(
        path.join("e2e").join("lp-open-fill-e2e.json"),
        serde_json::to_string_pretty(&manifest)?,
    )?;
    if let Some(auction_result_arguments) = fixture.auction_result_arguments.as_ref() {
        fs::write(
            path.join("e2e").join("auction-result-input.json"),
            serde_json::to_string_pretty(auction_result_arguments)?,
        )?;
    }
    Ok(())
}

fn storage_key(value: &str) -> String {
    value
        .chars()
        .flat_map(|character| {
            if character.is_ascii_alphanumeric() || character == '-' {
                vec![character]
            } else {
                let encoded = format!("_{:x}_", character as u32);
                encoded.chars().collect::<Vec<_>>()
            }
        })
        .collect()
}

fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis().min(u128::from(u64::MAX)) as u64)
        .unwrap_or(0)
}

fn build_smoke_arguments() -> Result<Vec<String>, Box<dyn Error>> {
    let batch_id = BatchId("stwo-smoke-batch-1".into());
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

    let transcript = SettlementTranscript {
        batch_id,
        pair_id: PairId("STRK/USDC".into()),
        batch_epoch: 1,
        order_commitment_root: "0x111".into(),
        encrypted_order_set_commitment: "0x222".into(),
        prior_note_root: "0x0".into(),
        prior_nullifier_root: "0x0".into(),
        prior_renewal_root: "0x0".into(),
        prior_fee_root: "0x0".into(),
        prior_liquidity_position_root: "0x0".into(),
        new_nullifier_root: "0x0".into(),
        new_renewal_root: "0x0".into(),
        new_liquidity_position_root: "0x0".into(),
        clearing_price: 0,
        price_base_scale: 1_000_000_000_000_000_000,
        taker_fee_bps: 4,
        relay_fee_bps: 0,
        protocol_fee_recipient: "0x4010".into(),
        relay_fee_recipient: "0x4020".into(),
        matched_orders: vec![],
        consumed_inputs: vec![],
        renewal_child_uses: vec![],
        liquidity_position_transitions: vec![],
        fees: vec![],
        output_notes: vec![],
        output_note_preimages: vec![],
        output_recovery_records: vec![],
        output_recovery_dummy_commitments,
        output_ciphertext_bundle_ref: output_bundle.bundle_commitment,
    };
    let witness = build_settlement_witness(
        &transcript,
        transcript.pair_id.clone(),
        "0x999",
        AssetId("STRK".into()),
        AssetId("USDC".into()),
        vec![],
    )?;

    Ok(build_stwo_serialized_input(&witness)?)
}

fn build_multi_pair_smoke_arguments() -> Result<Vec<String>, Box<dyn Error>> {
    let chosen = MultiPairFeasibilityProblem {
        batch_id: BatchId("stwo-smoke-multi-pair-1".into()),
        fills: vec![
            multi_pair_buy(MultiPairFillSpec {
                commitment: "0x101",
                pair: "ETH/USDC",
                base: "ETH",
                quote: "USDC",
                base_amount: 10,
                quote_amount: 25_000,
                limit_price: 2_500,
                fee_amount: 1,
            }),
            multi_pair_sell(MultiPairFillSpec {
                commitment: "0x102",
                pair: "STRK/USDC",
                base: "STRK",
                quote: "USDC",
                base_amount: 10_000,
                quote_amount: 10_000,
                limit_price: 1,
                fee_amount: 4,
            }),
        ],
        asset_deltas: vec![
            multi_pair_user_delta("0x101", "USDC", 25_000, MultiPairAssetDeltaDirection::In),
            multi_pair_user_delta("0x101", "ETH", 9, MultiPairAssetDeltaDirection::Out),
            multi_pair_fee_delta("0x101", "ETH", 1, MultiPairAssetDeltaDirection::Out),
            multi_pair_user_delta("0x102", "STRK", 10_000, MultiPairAssetDeltaDirection::In),
            multi_pair_user_delta("0x102", "USDC", 9_996, MultiPairAssetDeltaDirection::Out),
            multi_pair_fee_delta("0x102", "USDC", 4, MultiPairAssetDeltaDirection::Out),
            multi_pair_liquidity_delta("0x201", "ETH", 10, MultiPairAssetDeltaDirection::In),
            multi_pair_liquidity_delta("0x201", "USDC", 25_000, MultiPairAssetDeltaDirection::Out),
            multi_pair_liquidity_delta("0x202", "USDC", 10_000, MultiPairAssetDeltaDirection::In),
            multi_pair_liquidity_delta("0x202", "STRK", 10_000, MultiPairAssetDeltaDirection::Out),
        ],
    };
    let chosen_candidate = MultiPairCandidateSolution {
        solution_id: "chosen".into(),
        fills: chosen.fills.clone(),
        asset_deltas: chosen.asset_deltas.clone(),
    };
    let eth_only = MultiPairCandidateSolution {
        solution_id: "eth-only".into(),
        fills: vec![chosen.fills[0].clone()],
        asset_deltas: vec![
            multi_pair_user_delta("0x101", "USDC", 25_000, MultiPairAssetDeltaDirection::In),
            multi_pair_user_delta("0x101", "ETH", 9, MultiPairAssetDeltaDirection::Out),
            multi_pair_fee_delta("0x101", "ETH", 1, MultiPairAssetDeltaDirection::Out),
            multi_pair_liquidity_delta("0x201", "ETH", 10, MultiPairAssetDeltaDirection::In),
            multi_pair_liquidity_delta("0x201", "USDC", 25_000, MultiPairAssetDeltaDirection::Out),
        ],
    };
    let problem = MultiPairOptimalityProblem {
        chosen,
        eligible_order_commitments: vec![
            OrderCommitment("0x101".into()),
            OrderCommitment("0x102".into()),
        ],
        objective_weights: vec![
            MultiPairObjectiveWeight {
                asset_id: AssetId("ETH".into()),
                numerator: 2_500,
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
        candidate_solutions: vec![chosen_candidate, eth_only],
    };
    Ok(build_multi_pair_serialized_input(&problem)?)
}

fn build_lp_fill_smoke_arguments() -> Result<Vec<String>, Box<dyn Error>> {
    let seller_position = sample_position("0x101", "0x222", 1_000, 0, "0x333", "0x444");
    let buyer_position = sample_position("0x102", "0x223", 0, 50_000, "0x433", "0x544");
    let market_context = LiquidityPositionMarketContext {
        epoch: 12,
        observed_at_unix_ms: 1,
        current_time_unix_ms: 1,
        reference_price: 0,
        confirmation_price: None,
        price_base_scale: PRICE_SCALE_18,
    };
    let clearing_price = 350 * PRICE_SCALE_18;

    let mut position_state =
        LiquidityPositionState::from_positions(&[seller_position.clone(), buyer_position.clone()])?;
    let prior_position_root = position_state.root()?;

    let (next_seller_position, _) = apply_liquidity_position_fill(
        &seller_position,
        OrderSide::Sell,
        40,
        clearing_price,
        market_context.price_base_scale,
        "0x334",
    )?;
    let (_, _, seller_update) = position_state.replace(&seller_position, &next_seller_position)?;
    let seller_transition = liquidity_position_root_transition(
        LiquidityPositionTransitionKind::Update,
        Some(&seller_position),
        Some(&next_seller_position),
    )?;

    let (next_buyer_position, _) = apply_liquidity_position_fill(
        &buyer_position,
        OrderSide::Buy,
        40,
        clearing_price,
        market_context.price_base_scale,
        "0x434",
    )?;
    let (_, new_position_root, buyer_update) =
        position_state.replace(&buyer_position, &next_buyer_position)?;
    let buyer_transition = liquidity_position_root_transition(
        LiquidityPositionTransitionKind::Update,
        Some(&buyer_position),
        Some(&next_buyer_position),
    )?;

    let batch_id = BatchId("stwo-smoke-lp-fill-1".into());
    let output_bundle = OutputCiphertextBundle::from_ciphertexts(
        batch_id.clone(),
        "stwo-smoke-lp-fill-da",
        vec![],
    )?;
    let output_recovery_dummy_commitments = output_bundle
        .ciphertexts
        .iter()
        .map(|ciphertext| {
            ciphertext
                .recovery
                .as_ref()
                .map(|recovery| recovery.commitment.clone())
                .ok_or("padded LP-fill smoke ciphertext is missing its recovery commitment")
        })
        .collect::<Result<Vec<_>, _>>()?;

    let seller_witness = LiquidityPositionTransitionWitness {
        transition: seller_transition.clone(),
        prior_position: Some(seller_position),
        output_position: Some(next_seller_position),
        state_update: seller_update,
        epoch: market_context.epoch,
        fill: Some(LiquidityPositionSettlementFill {
            market_context: market_context.clone(),
            position_side: OrderSide::Sell,
            filled_base_amount: 40,
            clearing_price,
            price_base_scale: PRICE_SCALE_18,
        }),
        open_funding: None,
        output_notes: vec![],
        base_amount: 0,
        quote_amount: 0,
        lifecycle_authorization: None,
    };
    let buyer_witness = LiquidityPositionTransitionWitness {
        transition: buyer_transition.clone(),
        prior_position: Some(buyer_position),
        output_position: Some(next_buyer_position),
        state_update: buyer_update,
        epoch: market_context.epoch,
        fill: Some(LiquidityPositionSettlementFill {
            market_context,
            position_side: OrderSide::Buy,
            filled_base_amount: 40,
            clearing_price,
            price_base_scale: PRICE_SCALE_18,
        }),
        open_funding: None,
        output_notes: vec![],
        base_amount: 0,
        quote_amount: 0,
        lifecycle_authorization: None,
    };

    let transcript = SettlementTranscript {
        batch_id,
        pair_id: PairId("STRK/USDC".into()),
        batch_epoch: 12,
        order_commitment_root: "0x111".into(),
        encrypted_order_set_commitment: "0x222".into(),
        prior_note_root: "0x0".into(),
        prior_nullifier_root: "0x0".into(),
        prior_renewal_root: "0x0".into(),
        prior_fee_root: "0x0".into(),
        prior_liquidity_position_root: prior_position_root,
        new_nullifier_root: "0x0".into(),
        new_renewal_root: "0x0".into(),
        new_liquidity_position_root: new_position_root,
        clearing_price,
        price_base_scale: PRICE_SCALE_18,
        taker_fee_bps: 0,
        relay_fee_bps: 0,
        protocol_fee_recipient: "0x4010".into(),
        relay_fee_recipient: "0x4020".into(),
        matched_orders: vec![],
        consumed_inputs: vec![],
        renewal_child_uses: vec![],
        liquidity_position_transitions: vec![seller_transition, buyer_transition],
        fees: vec![],
        output_notes: vec![],
        output_note_preimages: vec![],
        output_recovery_records: vec![],
        output_recovery_dummy_commitments,
        output_ciphertext_bundle_ref: output_bundle.bundle_commitment,
    };
    let mut witness = build_settlement_witness(
        &transcript,
        transcript.pair_id.clone(),
        "0x999",
        AssetId("STRK".into()),
        AssetId("USDC".into()),
        vec![],
    )?;
    witness.liquidity_position_witnesses = vec![seller_witness, buyer_witness];

    Ok(build_stwo_serialized_input(&witness)?)
}

fn build_lp_user_fill_auction_result_smoke_arguments() -> Result<Vec<String>, Box<dyn Error>> {
    let pair_id = PairId("ETH/USDC".into());
    let base_asset_id = AssetId("ETH".into());
    let quote_asset_id = AssetId("USDC".into());
    let batch_id = BatchId("stwo-smoke-lp-user-fill-result-1".into());
    let epoch = 18;
    let clearing_price = 2_500 * USDC_SCALE_6;
    let fill_amount = PRICE_SCALE_18 / 10;
    let quote_amount = quote_amount_for_base_amount(fill_amount, clearing_price, PRICE_SCALE_18)?;
    let note_owner_public_key = note_recognition_public_key_from_raw_key_hex(&"11".repeat(32))?;
    let spend_key_felt = spend_auth_key_felt_from_raw_key_hex(&"22".repeat(32));
    let funding_spend_authority = spend_authority_from_raw_key_hex(&"22".repeat(32))?;
    let recipient_spend_authority = spend_authority_from_raw_key_hex(&"23".repeat(32))?;
    let recipient_withdraw_authority = withdraw_authority_from_raw_key_hex(&"24".repeat(32))?;

    let funding_note = Note {
        asset_id: quote_asset_id.clone(),
        amount: quote_amount,
        owner_public_key: note_owner_public_key.clone(),
        spend_authority: funding_spend_authority,
        withdraw_authority: withdraw_authority_from_raw_key_hex(&"25".repeat(32))?,
        blinding: "0x8801".into(),
        nonce: 1,
        metadata_commitment: "0x9801".into(),
    };
    let funding_note_commitment = funding_note.commitment()?;
    let funding_nullifier =
        nullifier_from_note_secret(&funding_note_commitment, &funding_note.blinding)?;
    let funding_note_ref =
        funding_input_set_commitment(std::slice::from_ref(&funding_note_commitment))?;
    let funding_nullifier_ref =
        funding_nullifier_set_commitment(std::slice::from_ref(&funding_nullifier))?;
    let order = OrderIntent {
        pair_id: pair_id.clone(),
        batch_id: batch_id.clone(),
        side: OrderSide::Buy,
        order_type: OrderType::LimitBatch,
        relay_mode: RelayMode::SelfRelay,
        limit_price: clearing_price,
        amount: fill_amount,
        min_fill: fill_amount,
        time_in_force: TimeInForce::CurrentBatchOnly,
        expiry_epoch: epoch,
        order_nonce: 701,
        parent_order_commitment: "0x0".into(),
        parent_child_index: 0,
        parent_secret_commitment: "0x0".into(),
        parent_cancel_authority: "0x0".into(),
        parent_authorization_secret: "0x0".into(),
        funding_note_ref: funding_note_ref.clone(),
        funding_nullifier: funding_nullifier_ref.clone(),
        recipient_owner_public_key: note_owner_public_key.clone(),
        recipient_spend_authority,
        recipient_withdraw_authority: recipient_withdraw_authority.clone(),
        recipient_residual_withdraw_authority: withdraw_authority_from_raw_key_hex(
            &"26".repeat(32),
        )?,
        auditor_view_allowed: false,
    };
    let order_commitment = order.commitment()?;
    let funding_authorization = sign_order_authorization(&spend_key_felt, &order_commitment)?;
    let order_root = ordered_felt_list_commitment(
        "zylith/batch-order-root",
        std::slice::from_ref(&order_commitment.0),
    )?;

    let seller_position = sample_position_for_pair(PositionSpec {
        position_id: "0x3301".into(),
        owner_authority: "0x4301".into(),
        base_reserve: 2 * PRICE_SCALE_18,
        quote_reserve: 0,
        blinding: "0x5301".into(),
        metadata_commitment: "0x6301".into(),
        pair_id: pair_id.clone(),
        base_asset_id: base_asset_id.clone(),
        quote_asset_id: quote_asset_id.clone(),
        price_lower_bound: 2_400 * USDC_SCALE_6,
        price_upper_bound: 2_600 * USDC_SCALE_6,
        max_fill_base_per_batch: PRICE_SCALE_18,
        opened_epoch: 1,
        expiry_epoch: 48,
    });
    let market_context = LiquidityPositionMarketContext {
        epoch,
        observed_at_unix_ms: 1_789_000_000_000,
        current_time_unix_ms: 1_789_000_006_000,
        reference_price: 0,
        confirmation_price: None,
        price_base_scale: PRICE_SCALE_18,
    };
    let mut position_state =
        LiquidityPositionState::from_positions(std::slice::from_ref(&seller_position))?;
    let prior_position_root = position_state.root()?;
    let (next_seller_position, _) = apply_liquidity_position_fill(
        &seller_position,
        OrderSide::Sell,
        fill_amount,
        clearing_price,
        PRICE_SCALE_18,
        "0x5302",
    )?;
    let (_, new_position_root, seller_state_update) =
        position_state.replace(&seller_position, &next_seller_position)?;
    let seller_transition = liquidity_position_root_transition(
        LiquidityPositionTransitionKind::Update,
        Some(&seller_position),
        Some(&next_seller_position),
    )?;
    let seller_witness = LiquidityPositionTransitionWitness {
        transition: seller_transition.clone(),
        prior_position: Some(seller_position),
        output_position: Some(next_seller_position),
        state_update: seller_state_update,
        epoch,
        fill: Some(LiquidityPositionSettlementFill {
            market_context,
            position_side: OrderSide::Sell,
            filled_base_amount: fill_amount,
            clearing_price,
            price_base_scale: PRICE_SCALE_18,
        }),
        open_funding: None,
        output_notes: vec![],
        base_amount: 0,
        quote_amount: 0,
        lifecycle_authorization: None,
    };

    let output_note = Note {
        asset_id: base_asset_id.clone(),
        amount: fill_amount,
        owner_public_key: note_owner_public_key.clone(),
        spend_authority: order.recipient_spend_authority.clone(),
        withdraw_authority: recipient_withdraw_authority,
        blinding: "0x8802".into(),
        nonce: 2,
        metadata_commitment: "0x9802".into(),
    };
    let (output_bundle, output_notes, output_recovery_records, output_recovery_dummy_commitments) =
        output_bundle_for_notes(
            batch_id.clone(),
            "stwo-smoke-lp-user-fill-result-da",
            std::slice::from_ref(&output_note),
        )?;
    let consumed_input = ConsumedInput {
        note_commitment: funding_note_commitment.clone(),
        nullifier: funding_nullifier_ref.clone(),
    };
    let (_, new_nullifier_root, _) = nullifier_sparse_update_witnesses_for_consumed_inputs(
        &[],
        std::slice::from_ref(&consumed_input),
    )?;
    let prior_note_root =
        settlement_note_root_after_deposit_roots(&[deposit_root_from_note(&funding_note)?])?;

    let transcript = SettlementTranscript {
        batch_id: batch_id.clone(),
        pair_id: pair_id.clone(),
        batch_epoch: epoch,
        order_commitment_root: order_root,
        encrypted_order_set_commitment: "0x222".into(),
        prior_note_root,
        prior_nullifier_root: "0x0".into(),
        prior_renewal_root: "0x0".into(),
        prior_fee_root: "0x0".into(),
        prior_liquidity_position_root: prior_position_root,
        new_nullifier_root,
        new_renewal_root: "0x0".into(),
        new_liquidity_position_root: new_position_root,
        clearing_price,
        price_base_scale: PRICE_SCALE_18,
        taker_fee_bps: 0,
        relay_fee_bps: 0,
        protocol_fee_recipient: "0x4010".into(),
        relay_fee_recipient: "0x4020".into(),
        matched_orders: vec![MatchedOrder {
            order_commitment: order_commitment.clone(),
            filled_amount: fill_amount,
        }],
        consumed_inputs: vec![consumed_input],
        renewal_child_uses: vec![],
        liquidity_position_transitions: vec![seller_transition],
        fees: vec![],
        output_notes,
        output_note_preimages: vec![output_note.clone()],
        output_recovery_records,
        output_recovery_dummy_commitments,
        output_ciphertext_bundle_ref: output_bundle.bundle_commitment,
    };
    let mut witness = build_settlement_witness(
        &transcript,
        pair_id,
        "0x999",
        base_asset_id,
        quote_asset_id,
        vec![MatchedOrderWitness {
            order_commitment: order_commitment.clone(),
            funding_note: funding_note.clone(),
            funding_notes: vec![funding_note.clone()],
            funding_note_ref,
            funding_nullifier: funding_nullifier_ref.clone(),
            funding_nullifiers: vec![funding_nullifier],
            funding_authorization: funding_authorization.clone(),
            side: order.side.clone(),
            order_type: order.order_type.clone(),
            relay_mode: order.relay_mode.clone(),
            liquidity_provider_band_attribution: None,
            limit_price: order.limit_price,
            order_amount: order.amount,
            min_fill: order.min_fill,
            time_in_force: order.time_in_force.clone(),
            expiry_epoch: order.expiry_epoch,
            order_nonce: order.order_nonce,
            parent_order_commitment: order.parent_order_commitment.clone(),
            parent_child_index: order.parent_child_index,
            parent_secret_commitment: order.parent_secret_commitment.clone(),
            parent_cancel_authority: order.parent_cancel_authority.clone(),
            parent_authorization_secret: order.parent_authorization_secret.clone(),
            auditor_view_allowed: order.auditor_view_allowed,
            recipient_owner_public_key: order.recipient_owner_public_key.clone(),
            recipient_spend_authority: order.recipient_spend_authority.clone(),
            recipient_withdraw_authority: order.recipient_withdraw_authority.clone(),
            recipient_residual_withdraw_authority: order
                .recipient_residual_withdraw_authority
                .clone(),
            filled_amount: fill_amount,
            output_note,
            residual_note: None,
        }],
    )?;
    witness.liquidity_position_witnesses = vec![seller_witness];
    let auction_order_witness = AuctionOrderWitness {
        order_commitment,
        order,
        funding_note: funding_note.clone(),
        funding_notes: vec![funding_note],
        funding_authorization,
    };

    Ok(build_auction_result_serialized_input(
        &witness,
        std::slice::from_ref(&auction_order_witness),
    )?)
}

fn build_lp_soak_smoke_arguments() -> Result<Vec<String>, Box<dyn Error>> {
    let pair_id = PairId("ETH/USDC".into());
    let base_asset_id = AssetId("ETH".into());
    let quote_asset_id = AssetId("USDC".into());
    let lower_price = 2_400 * USDC_SCALE_6;
    let clearing_price = 2_500 * USDC_SCALE_6;
    let upper_price = 2_600 * USDC_SCALE_6;
    let max_fill = PRICE_SCALE_18;
    let market_context = LiquidityPositionMarketContext {
        epoch: 24,
        observed_at_unix_ms: 1_789_000_000_000,
        current_time_unix_ms: 1_789_000_006_000,
        reference_price: 0,
        confirmation_price: None,
        price_base_scale: PRICE_SCALE_18,
    };
    let fill_amounts = [
        50_000_000_000_000_000_u128,
        75_000_000_000_000_000,
        100_000_000_000_000_000,
        125_000_000_000_000_000,
        150_000_000_000_000_000,
        180_000_000_000_000_000,
    ];

    let mut sellers = Vec::with_capacity(fill_amounts.len());
    let mut buyers = Vec::with_capacity(fill_amounts.len());
    for index in 0..fill_amounts.len() {
        sellers.push(sample_position_for_pair(PositionSpec {
            position_id: format!("0x{:x}", 0x5000 + index),
            owner_authority: format!("0x{:x}", 0x6000 + index),
            base_reserve: (5 + index as u128) * PRICE_SCALE_18,
            quote_reserve: 0,
            blinding: format!("0x{:x}", 0x7000 + index),
            metadata_commitment: format!("0x{:x}", 0x8000 + index),
            pair_id: pair_id.clone(),
            base_asset_id: base_asset_id.clone(),
            quote_asset_id: quote_asset_id.clone(),
            price_lower_bound: lower_price,
            price_upper_bound: upper_price,
            max_fill_base_per_batch: max_fill,
            opened_epoch: 1,
            expiry_epoch: 48,
        }));
        buyers.push(sample_position_for_pair(PositionSpec {
            position_id: format!("0x{:x}", 0x5100 + index),
            owner_authority: format!("0x{:x}", 0x6100 + index),
            base_reserve: 0,
            quote_reserve: (30_000 + index as u128 * 1_000) * USDC_SCALE_6,
            blinding: format!("0x{:x}", 0x7100 + index),
            metadata_commitment: format!("0x{:x}", 0x8100 + index),
            pair_id: pair_id.clone(),
            base_asset_id: base_asset_id.clone(),
            quote_asset_id: quote_asset_id.clone(),
            price_lower_bound: lower_price,
            price_upper_bound: upper_price,
            max_fill_base_per_batch: max_fill,
            opened_epoch: 1,
            expiry_epoch: 48,
        }));
    }

    let mut initial_positions = sellers.clone();
    initial_positions.extend(buyers.clone());
    let mut position_state = LiquidityPositionState::from_positions(&initial_positions)?;
    let prior_position_root = position_state.root()?;
    let mut transitions: Vec<LiquidityPositionRootTransition> = Vec::new();
    let mut witnesses: Vec<LiquidityPositionTransitionWitness> = Vec::new();

    for (index, fill_amount) in fill_amounts.iter().copied().enumerate() {
        append_fill_transition(
            &mut position_state,
            &mut transitions,
            &mut witnesses,
            sellers[index].clone(),
            OrderSide::Sell,
            fill_amount,
            &market_context,
            clearing_price,
            format!("0x{:x}", 0x9000 + index),
        )?;
        append_fill_transition(
            &mut position_state,
            &mut transitions,
            &mut witnesses,
            buyers[index].clone(),
            OrderSide::Buy,
            fill_amount,
            &market_context,
            clearing_price,
            format!("0x{:x}", 0x9100 + index),
        )?;
    }
    let new_position_root = position_state.root()?;

    let batch_id = BatchId("stwo-smoke-lp-soak-eth-usdc-24".into());
    let output_bundle = OutputCiphertextBundle::from_ciphertexts(
        batch_id.clone(),
        "stwo-smoke-lp-soak-da",
        vec![],
    )?;
    let output_recovery_dummy_commitments = output_bundle
        .ciphertexts
        .iter()
        .map(|ciphertext| {
            ciphertext
                .recovery
                .as_ref()
                .map(|recovery| recovery.commitment.clone())
                .ok_or("padded LP-soak smoke ciphertext is missing its recovery commitment")
        })
        .collect::<Result<Vec<_>, _>>()?;

    let transcript = SettlementTranscript {
        batch_id,
        pair_id,
        batch_epoch: market_context.epoch,
        order_commitment_root: "0x111".into(),
        encrypted_order_set_commitment: "0x222".into(),
        prior_note_root: "0x0".into(),
        prior_nullifier_root: "0x0".into(),
        prior_renewal_root: "0x0".into(),
        prior_fee_root: "0x0".into(),
        prior_liquidity_position_root: prior_position_root,
        new_nullifier_root: "0x0".into(),
        new_renewal_root: "0x0".into(),
        new_liquidity_position_root: new_position_root,
        clearing_price,
        price_base_scale: PRICE_SCALE_18,
        taker_fee_bps: 0,
        relay_fee_bps: 0,
        protocol_fee_recipient: "0x4010".into(),
        relay_fee_recipient: "0x4020".into(),
        matched_orders: vec![],
        consumed_inputs: vec![],
        renewal_child_uses: vec![],
        liquidity_position_transitions: transitions.clone(),
        fees: vec![],
        output_notes: vec![],
        output_note_preimages: vec![],
        output_recovery_records: vec![],
        output_recovery_dummy_commitments,
        output_ciphertext_bundle_ref: output_bundle.bundle_commitment,
    };
    let mut witness = build_settlement_witness(
        &transcript,
        transcript.pair_id.clone(),
        "0x999",
        base_asset_id,
        quote_asset_id,
        vec![],
    )?;
    witness.liquidity_position_witnesses = witnesses;

    Ok(build_stwo_serialized_input(&witness)?)
}

fn build_lp_lifecycle_smoke_arguments() -> Result<Vec<String>, Box<dyn Error>> {
    let pair_id = PairId("ETH/USDC".into());
    let base_asset_id = AssetId("ETH".into());
    let quote_asset_id = AssetId("USDC".into());
    let epoch = 32;
    let clearing_price = 2_500 * USDC_SCALE_6;
    let fill_amount = PRICE_SCALE_18 / 10;
    let seller_private_key = "0x1e240";
    let buyer_private_key = "0x1e241";
    let seller_owner = owner_authority_from_private_key(seller_private_key)?;
    let buyer_owner = owner_authority_from_private_key(buyer_private_key)?;
    let note_owner_public_key = note_recognition_public_key_from_raw_key_hex(&"11".repeat(32))?;

    let seller_funding_note = sample_owner_note(NoteSpec {
        asset_id: base_asset_id.clone(),
        amount: 2 * PRICE_SCALE_18,
        owner_authority: seller_owner.clone(),
        owner_public_key: note_owner_public_key.clone(),
        blinding: "0xa101".into(),
        nonce: 101,
        metadata_commitment: "0xb101".into(),
    });
    let buyer_funding_note = sample_owner_note(NoteSpec {
        asset_id: quote_asset_id.clone(),
        amount: 1_000 * USDC_SCALE_6,
        owner_authority: buyer_owner.clone(),
        owner_public_key: note_owner_public_key.clone(),
        blinding: "0xa102".into(),
        nonce: 102,
        metadata_commitment: "0xb102".into(),
    });
    let seller_funding_commitment = seller_funding_note.commitment()?;
    let buyer_funding_commitment = buyer_funding_note.commitment()?;
    let seller_funding_nullifier =
        nullifier_from_note_secret(&seller_funding_commitment, &seller_funding_note.blinding)?;
    let buyer_funding_nullifier =
        nullifier_from_note_secret(&buyer_funding_commitment, &buyer_funding_note.blinding)?;
    let consumed_inputs = vec![
        ConsumedInput {
            note_commitment: seller_funding_commitment,
            nullifier: seller_funding_nullifier,
        },
        ConsumedInput {
            note_commitment: buyer_funding_commitment,
            nullifier: buyer_funding_nullifier,
        },
    ];

    let seller_open = position_with_policy(
        PositionSpec {
            position_id: "0x6201".into(),
            owner_authority: seller_owner.clone(),
            base_reserve: 2 * PRICE_SCALE_18,
            quote_reserve: 0,
            blinding: "0xc101".into(),
            metadata_commitment: "0xd101".into(),
            pair_id: pair_id.clone(),
            base_asset_id: base_asset_id.clone(),
            quote_asset_id: quote_asset_id.clone(),
            price_lower_bound: 2_360 * USDC_SCALE_6,
            price_upper_bound: 2_600 * USDC_SCALE_6,
            max_fill_base_per_batch: PRICE_SCALE_18 / 2,
            opened_epoch: epoch,
            expiry_epoch: 80,
        },
        LiquidityPositionCurvePolicy {
            kind: LiquidityPositionCurveKind::StaticRange,
            band_count: 3,
            spread_bps: 0,
            target_base_ratio_bps: 5_000,
            inventory_skew_bps: 0,
            max_price_deviation_bps: 0,
        },
        None,
    );
    let buyer_open = position_with_policy(
        PositionSpec {
            position_id: "0x6202".into(),
            owner_authority: buyer_owner.clone(),
            base_reserve: 0,
            quote_reserve: 1_000 * USDC_SCALE_6,
            blinding: "0xc102".into(),
            metadata_commitment: "0xd102".into(),
            pair_id: pair_id.clone(),
            base_asset_id: base_asset_id.clone(),
            quote_asset_id: quote_asset_id.clone(),
            price_lower_bound: 2_400 * USDC_SCALE_6,
            price_upper_bound: 2_640 * USDC_SCALE_6,
            max_fill_base_per_batch: PRICE_SCALE_18 / 2,
            opened_epoch: epoch,
            expiry_epoch: 80,
        },
        LiquidityPositionCurvePolicy {
            kind: LiquidityPositionCurveKind::StaticRange,
            band_count: 3,
            spread_bps: 0,
            target_base_ratio_bps: 5_000,
            inventory_skew_bps: 0,
            max_price_deviation_bps: 0,
        },
        None,
    );

    let mut position_state = LiquidityPositionState::new();
    let prior_position_root = position_state.root()?;
    let (_, _, seller_open_update) = position_state.open(&seller_open)?;
    let (_, _, buyer_open_update) = position_state.open(&buyer_open)?;
    let seller_open_transition = liquidity_position_root_transition(
        LiquidityPositionTransitionKind::Open,
        None,
        Some(&seller_open),
    )?;
    let buyer_open_transition = liquidity_position_root_transition(
        LiquidityPositionTransitionKind::Open,
        None,
        Some(&buyer_open),
    )?;
    let seller_open_auth = sign_liquidity_position_transition(
        seller_private_key,
        LiquidityPositionTransitionKind::Open,
        &seller_open.position_id,
        None,
        Some(&seller_open.commitment()?),
        epoch,
        0,
        0,
    )?;
    let buyer_open_auth = sign_liquidity_position_transition(
        buyer_private_key,
        LiquidityPositionTransitionKind::Open,
        &buyer_open.position_id,
        None,
        Some(&buyer_open.commitment()?),
        epoch,
        0,
        0,
    )?;

    let mut seller_reconfigured = seller_open.clone();
    seller_reconfigured.max_fill_base_per_batch = PRICE_SCALE_18;
    seller_reconfigured.expiry_epoch = 96;
    seller_reconfigured.blinding = "0xc201".into();
    seller_reconfigured.metadata_commitment = "0xd201".into();
    let reconfigure_auth = sign_liquidity_position_transition(
        seller_private_key,
        LiquidityPositionTransitionKind::Reconfigure,
        &seller_open.position_id,
        Some(&seller_open.commitment()?),
        Some(&seller_reconfigured.commitment()?),
        epoch,
        0,
        0,
    )?;
    let (_, _, reconfigure_update) = position_state.replace(&seller_open, &seller_reconfigured)?;
    let reconfigure_transition = liquidity_position_root_transition(
        LiquidityPositionTransitionKind::Reconfigure,
        Some(&seller_open),
        Some(&seller_reconfigured),
    )?;

    let market_context = LiquidityPositionMarketContext {
        epoch,
        observed_at_unix_ms: 1_789_000_000_000,
        current_time_unix_ms: 1_789_000_004_000,
        reference_price: 0,
        confirmation_price: None,
        price_base_scale: PRICE_SCALE_18,
    };
    let (seller_filled, _) = apply_liquidity_position_fill(
        &seller_reconfigured,
        OrderSide::Sell,
        fill_amount,
        clearing_price,
        PRICE_SCALE_18,
        "0xc301",
    )?;
    let (_, _, seller_fill_update) =
        position_state.replace(&seller_reconfigured, &seller_filled)?;
    let seller_fill_transition = liquidity_position_root_transition(
        LiquidityPositionTransitionKind::Update,
        Some(&seller_reconfigured),
        Some(&seller_filled),
    )?;
    let (buyer_filled, _) = apply_liquidity_position_fill(
        &buyer_open,
        OrderSide::Buy,
        fill_amount,
        clearing_price,
        PRICE_SCALE_18,
        "0xc302",
    )?;
    let (_, _, buyer_fill_update) = position_state.replace(&buyer_open, &buyer_filled)?;
    let buyer_fill_transition = liquidity_position_root_transition(
        LiquidityPositionTransitionKind::Update,
        Some(&buyer_open),
        Some(&buyer_filled),
    )?;

    let buyer_base_note = sample_owner_note(NoteSpec {
        asset_id: base_asset_id.clone(),
        amount: buyer_filled.base_reserve,
        owner_authority: buyer_owner.clone(),
        owner_public_key: note_owner_public_key.clone(),
        blinding: "0xa301".into(),
        nonce: 301,
        metadata_commitment: "0xb301".into(),
    });
    let buyer_quote_note = sample_owner_note(NoteSpec {
        asset_id: quote_asset_id.clone(),
        amount: buyer_filled.quote_reserve,
        owner_authority: buyer_owner.clone(),
        owner_public_key: note_owner_public_key.clone(),
        blinding: "0xa302".into(),
        nonce: 302,
        metadata_commitment: "0xb302".into(),
    });
    let close_auth = sign_liquidity_position_transition(
        buyer_private_key,
        LiquidityPositionTransitionKind::Close,
        &buyer_filled.position_id,
        Some(&buyer_filled.commitment()?),
        None,
        epoch,
        buyer_base_note.amount,
        buyer_quote_note.amount,
    )?;
    close_liquidity_position(
        &buyer_filled,
        epoch,
        vec![buyer_base_note.clone(), buyer_quote_note.clone()],
        &close_auth,
    )?;
    let (_, _, close_update) = position_state.close(&buyer_filled)?;
    let close_transition = liquidity_position_root_transition(
        LiquidityPositionTransitionKind::Close,
        Some(&buyer_filled),
        None,
    )?;

    let transitions = vec![
        seller_open_transition.clone(),
        buyer_open_transition.clone(),
        reconfigure_transition.clone(),
        seller_fill_transition.clone(),
        buyer_fill_transition.clone(),
        close_transition.clone(),
    ];
    let lifecycle_output_notes = vec![buyer_base_note.clone(), buyer_quote_note.clone()];
    let batch_id = BatchId("stwo-smoke-lp-lifecycle-eth-usdc-32".into());
    let (output_bundle, output_note_records, output_recovery_records, output_dummy_commitments) =
        output_bundle_for_notes(
            batch_id.clone(),
            "stwo-smoke-lp-lifecycle-da",
            &lifecycle_output_notes,
        )?;
    let prior_note_root = settlement_note_root_after_deposit_roots(&[
        deposit_root_from_note(&seller_funding_note)?,
        deposit_root_from_note(&buyer_funding_note)?,
    ])?;
    let new_nullifier_root =
        nullifier_sparse_update_witnesses_for_consumed_inputs(&[], &consumed_inputs)?.1;
    let new_position_root = position_state.root()?;

    let transcript = SettlementTranscript {
        batch_id,
        pair_id,
        batch_epoch: epoch,
        order_commitment_root: "0x111".into(),
        encrypted_order_set_commitment: "0x222".into(),
        prior_note_root,
        prior_nullifier_root: "0x0".into(),
        prior_renewal_root: "0x0".into(),
        prior_fee_root: "0x0".into(),
        prior_liquidity_position_root: prior_position_root,
        new_nullifier_root,
        new_renewal_root: "0x0".into(),
        new_liquidity_position_root: new_position_root,
        clearing_price,
        price_base_scale: PRICE_SCALE_18,
        taker_fee_bps: 0,
        relay_fee_bps: 0,
        protocol_fee_recipient: "0x4010".into(),
        relay_fee_recipient: "0x4020".into(),
        matched_orders: vec![],
        consumed_inputs,
        renewal_child_uses: vec![],
        liquidity_position_transitions: transitions,
        fees: vec![],
        output_notes: output_note_records,
        output_note_preimages: lifecycle_output_notes,
        output_recovery_records,
        output_recovery_dummy_commitments: output_dummy_commitments,
        output_ciphertext_bundle_ref: output_bundle.bundle_commitment,
    };
    let mut witness = build_settlement_witness(
        &transcript,
        transcript.pair_id.clone(),
        "0x999",
        base_asset_id,
        quote_asset_id,
        vec![],
    )?;
    witness.liquidity_position_witnesses = vec![
        LiquidityPositionTransitionWitness {
            transition: seller_open_transition,
            prior_position: None,
            output_position: Some(seller_open.clone()),
            state_update: seller_open_update,
            epoch,
            fill: None,
            open_funding: Some(LiquidityPositionOpenFunding {
                input_notes: vec![seller_funding_note],
                change_notes: vec![],
                authorization: seller_open_auth,
            }),
            output_notes: vec![],
            base_amount: 0,
            quote_amount: 0,
            lifecycle_authorization: None,
        },
        LiquidityPositionTransitionWitness {
            transition: buyer_open_transition,
            prior_position: None,
            output_position: Some(buyer_open.clone()),
            state_update: buyer_open_update,
            epoch,
            fill: None,
            open_funding: Some(LiquidityPositionOpenFunding {
                input_notes: vec![buyer_funding_note],
                change_notes: vec![],
                authorization: buyer_open_auth,
            }),
            output_notes: vec![],
            base_amount: 0,
            quote_amount: 0,
            lifecycle_authorization: None,
        },
        LiquidityPositionTransitionWitness {
            transition: reconfigure_transition,
            prior_position: Some(seller_open),
            output_position: Some(seller_reconfigured.clone()),
            state_update: reconfigure_update,
            epoch,
            fill: None,
            open_funding: None,
            output_notes: vec![],
            base_amount: 0,
            quote_amount: 0,
            lifecycle_authorization: Some(reconfigure_auth),
        },
        LiquidityPositionTransitionWitness {
            transition: seller_fill_transition,
            prior_position: Some(seller_reconfigured),
            output_position: Some(seller_filled.clone()),
            state_update: seller_fill_update,
            epoch,
            fill: Some(LiquidityPositionSettlementFill {
                market_context: market_context.clone(),
                position_side: OrderSide::Sell,
                filled_base_amount: fill_amount,
                clearing_price,
                price_base_scale: PRICE_SCALE_18,
            }),
            open_funding: None,
            output_notes: vec![],
            base_amount: 0,
            quote_amount: 0,
            lifecycle_authorization: None,
        },
        LiquidityPositionTransitionWitness {
            transition: buyer_fill_transition,
            prior_position: Some(buyer_open),
            output_position: Some(buyer_filled.clone()),
            state_update: buyer_fill_update,
            epoch,
            fill: Some(LiquidityPositionSettlementFill {
                market_context,
                position_side: OrderSide::Buy,
                filled_base_amount: fill_amount,
                clearing_price,
                price_base_scale: PRICE_SCALE_18,
            }),
            open_funding: None,
            output_notes: vec![],
            base_amount: 0,
            quote_amount: 0,
            lifecycle_authorization: None,
        },
        LiquidityPositionTransitionWitness {
            transition: close_transition,
            prior_position: Some(buyer_filled),
            output_position: None,
            state_update: close_update,
            epoch,
            fill: None,
            open_funding: None,
            output_notes: vec![buyer_base_note, buyer_quote_note],
            base_amount: 0,
            quote_amount: 0,
            lifecycle_authorization: Some(close_auth),
        },
    ];

    Ok(build_stwo_serialized_input(&witness)?)
}

fn build_lp_open_fill_e2e_smoke_fixture() -> Result<SmokeFixture, Box<dyn Error>> {
    let pair_id = PairId("ETH/USDC".into());
    let base_asset_id = AssetId("ETH".into());
    let quote_asset_id = AssetId("USDC".into());
    let epoch = 45;
    let clearing_price = 2_500 * USDC_SCALE_6;
    let fill_amount = PRICE_SCALE_18 / 10;
    let seller_private_key = "0x2e240";
    let buyer_private_key = "0x2e241";
    let seller_owner = owner_authority_from_private_key(seller_private_key)?;
    let buyer_owner = owner_authority_from_private_key(buyer_private_key)?;
    let note_owner_public_key = note_recognition_public_key_from_raw_key_hex(&"12".repeat(32))?;
    let fee_config = live_smoke_fee_config()?;
    let auction_verifier_address = live_smoke_auction_verifier_address();

    let seller_funding_note = sample_owner_note(NoteSpec {
        asset_id: base_asset_id.clone(),
        amount: 2 * PRICE_SCALE_18,
        owner_authority: seller_owner.clone(),
        owner_public_key: note_owner_public_key.clone(),
        blinding: "0xe101".into(),
        nonce: 401,
        metadata_commitment: "0xf101".into(),
    });
    let buyer_funding_note = sample_owner_note(NoteSpec {
        asset_id: quote_asset_id.clone(),
        amount: 1_000 * USDC_SCALE_6,
        owner_authority: buyer_owner.clone(),
        owner_public_key: note_owner_public_key,
        blinding: "0xe102".into(),
        nonce: 402,
        metadata_commitment: "0xf102".into(),
    });
    let seller_activation = funding_activation_from_note(&seller_funding_note)?;
    let buyer_activation = funding_activation_from_note(&buyer_funding_note)?;
    let seller_funding_commitment = seller_funding_note.commitment()?;
    let buyer_funding_commitment = buyer_funding_note.commitment()?;
    let seller_funding_nullifier =
        nullifier_from_note_secret(&seller_funding_commitment, &seller_funding_note.blinding)?;
    let buyer_funding_nullifier =
        nullifier_from_note_secret(&buyer_funding_commitment, &buyer_funding_note.blinding)?;
    let consumed_inputs = vec![
        ConsumedInput {
            note_commitment: seller_funding_commitment,
            nullifier: seller_funding_nullifier,
        },
        ConsumedInput {
            note_commitment: buyer_funding_commitment,
            nullifier: buyer_funding_nullifier,
        },
    ];

    let seller_open = position_with_policy(
        PositionSpec {
            position_id: "0x8201".into(),
            owner_authority: seller_owner.clone(),
            base_reserve: 2 * PRICE_SCALE_18,
            quote_reserve: 0,
            blinding: "0xe201".into(),
            metadata_commitment: "0xf201".into(),
            pair_id: pair_id.clone(),
            base_asset_id: base_asset_id.clone(),
            quote_asset_id: quote_asset_id.clone(),
            price_lower_bound: 2_350 * USDC_SCALE_6,
            price_upper_bound: 2_650 * USDC_SCALE_6,
            max_fill_base_per_batch: PRICE_SCALE_18 / 2,
            opened_epoch: epoch,
            expiry_epoch: 96,
        },
        LiquidityPositionCurvePolicy {
            kind: LiquidityPositionCurveKind::StaticRange,
            band_count: 3,
            spread_bps: 0,
            target_base_ratio_bps: 5_000,
            inventory_skew_bps: 0,
            max_price_deviation_bps: 0,
        },
        None,
    );
    let buyer_open = position_with_policy(
        PositionSpec {
            position_id: "0x8202".into(),
            owner_authority: buyer_owner.clone(),
            base_reserve: 0,
            quote_reserve: 1_000 * USDC_SCALE_6,
            blinding: "0xe202".into(),
            metadata_commitment: "0xf202".into(),
            pair_id: pair_id.clone(),
            base_asset_id: base_asset_id.clone(),
            quote_asset_id: quote_asset_id.clone(),
            price_lower_bound: 2_350 * USDC_SCALE_6,
            price_upper_bound: 2_650 * USDC_SCALE_6,
            max_fill_base_per_batch: PRICE_SCALE_18 / 2,
            opened_epoch: epoch,
            expiry_epoch: 96,
        },
        LiquidityPositionCurvePolicy {
            kind: LiquidityPositionCurveKind::StaticRange,
            band_count: 3,
            spread_bps: 0,
            target_base_ratio_bps: 5_000,
            inventory_skew_bps: 0,
            max_price_deviation_bps: 0,
        },
        None,
    );

    let mut position_state = LiquidityPositionState::new();
    let prior_position_root = position_state.root()?;
    let (_, _, seller_open_update) = position_state.open(&seller_open)?;
    let (_, _, buyer_open_update) = position_state.open(&buyer_open)?;
    let seller_open_transition = liquidity_position_root_transition(
        LiquidityPositionTransitionKind::Open,
        None,
        Some(&seller_open),
    )?;
    let buyer_open_transition = liquidity_position_root_transition(
        LiquidityPositionTransitionKind::Open,
        None,
        Some(&buyer_open),
    )?;
    let seller_open_auth = sign_liquidity_position_transition(
        seller_private_key,
        LiquidityPositionTransitionKind::Open,
        &seller_open.position_id,
        None,
        Some(&seller_open.commitment()?),
        epoch,
        0,
        0,
    )?;
    let buyer_open_auth = sign_liquidity_position_transition(
        buyer_private_key,
        LiquidityPositionTransitionKind::Open,
        &buyer_open.position_id,
        None,
        Some(&buyer_open.commitment()?),
        epoch,
        0,
        0,
    )?;

    let market_context = LiquidityPositionMarketContext {
        epoch,
        observed_at_unix_ms: 1_789_000_000_000,
        current_time_unix_ms: 1_789_000_006_000,
        reference_price: clearing_price,
        confirmation_price: Some(2_501 * USDC_SCALE_6),
        price_base_scale: PRICE_SCALE_18,
    };
    let (seller_filled, _) = apply_liquidity_position_fill(
        &seller_open,
        OrderSide::Sell,
        fill_amount,
        clearing_price,
        PRICE_SCALE_18,
        "0xe301",
    )?;
    let (_, _, seller_fill_update) = position_state.replace(&seller_open, &seller_filled)?;
    let seller_fill_transition = liquidity_position_root_transition(
        LiquidityPositionTransitionKind::Update,
        Some(&seller_open),
        Some(&seller_filled),
    )?;
    let (buyer_filled, _) = apply_liquidity_position_fill(
        &buyer_open,
        OrderSide::Buy,
        fill_amount,
        clearing_price,
        PRICE_SCALE_18,
        "0xe302",
    )?;
    let (_, _, buyer_fill_update) = position_state.replace(&buyer_open, &buyer_filled)?;
    let buyer_fill_transition = liquidity_position_root_transition(
        LiquidityPositionTransitionKind::Update,
        Some(&buyer_open),
        Some(&buyer_filled),
    )?;
    let transitions = vec![
        seller_open_transition.clone(),
        buyer_open_transition.clone(),
        seller_fill_transition.clone(),
        buyer_fill_transition.clone(),
    ];
    let batch_id = BatchId("sepolia-lp-open-fill-e2e-46".into());
    let cover_batch = BatchSummary {
        batch_id: batch_id.clone(),
        pair_id: pair_id.clone(),
        epoch_id: epoch,
        close_time_unix_ms: 0,
        status: BatchStatus::Closed,
        order_count: heartbeat_cover_order_count(0) as u64,
        order_commitment_root: "0x0".into(),
        encrypted_order_set_commitment: "0x0".into(),
    };
    let auction_order_witnesses = build_heartbeat_cover_orders(
        "smoke-heartbeat-cover-secret",
        &cover_batch,
        &base_asset_id,
        &quote_asset_id,
        clearing_price,
        0,
    )?
    .into_iter()
    .map(|cover| AuctionOrderWitness {
        order_commitment: cover.order_commitment,
        order: cover.payload.order,
        funding_note: cover.payload.funding_note,
        funding_notes: cover.payload.funding_notes,
        funding_authorization: cover.payload.funding_authorization,
    })
    .collect::<Vec<_>>();
    let order_commitment_root = ordered_felt_list_commitment(
        "zylith/batch-order-root",
        &auction_order_witnesses
            .iter()
            .map(|witness| witness.order_commitment.0.clone())
            .collect::<Vec<_>>(),
    )?;
    let output_bundle = OutputCiphertextBundle::from_ciphertexts(
        batch_id.clone(),
        "sepolia-lp-open-fill-e2e-da",
        vec![],
    )?;
    let output_recovery_dummy_commitments = output_bundle
        .ciphertexts
        .iter()
        .map(|ciphertext| {
            ciphertext
                .recovery
                .as_ref()
                .map(|recovery| recovery.commitment.clone())
                .ok_or("padded LP E2E ciphertext is missing its recovery commitment")
        })
        .collect::<Result<Vec<_>, _>>()?;
    let prior_note_root = settlement_note_root_after_deposit_roots(&[
        seller_activation.deposit_root.clone(),
        buyer_activation.deposit_root.clone(),
    ])?;
    let (_, new_nullifier_root, nullifier_sparse_witnesses) =
        nullifier_sparse_update_witnesses_for_consumed_inputs(&[], &consumed_inputs)?;
    let transcript = SettlementTranscript {
        batch_id: batch_id.clone(),
        pair_id: pair_id.clone(),
        batch_epoch: epoch,
        order_commitment_root,
        encrypted_order_set_commitment: "0x222".into(),
        prior_note_root,
        prior_nullifier_root: "0x0".into(),
        prior_renewal_root: "0x0".into(),
        prior_fee_root: "0x0".into(),
        prior_liquidity_position_root: prior_position_root,
        new_nullifier_root,
        new_renewal_root: "0x0".into(),
        new_liquidity_position_root: position_state.root()?,
        clearing_price,
        price_base_scale: PRICE_SCALE_18,
        taker_fee_bps: fee_config.taker_fee_bps,
        relay_fee_bps: fee_config.relay_fee_bps,
        protocol_fee_recipient: fee_config.protocol_fee_recipient,
        relay_fee_recipient: fee_config.relay_fee_recipient,
        matched_orders: vec![],
        consumed_inputs,
        renewal_child_uses: vec![],
        liquidity_position_transitions: transitions,
        fees: vec![],
        output_notes: vec![],
        output_note_preimages: vec![],
        output_recovery_records: vec![],
        output_recovery_dummy_commitments,
        output_ciphertext_bundle_ref: output_bundle.bundle_commitment.clone(),
    };
    let mut witness = build_settlement_witness(
        &transcript,
        pair_id,
        &auction_verifier_address,
        base_asset_id,
        quote_asset_id,
        vec![],
    )?;
    witness.nullifier_sparse_witnesses = nullifier_sparse_witnesses;
    witness.liquidity_position_witnesses = vec![
        LiquidityPositionTransitionWitness {
            transition: seller_open_transition,
            prior_position: None,
            output_position: Some(seller_open.clone()),
            state_update: seller_open_update,
            epoch,
            fill: None,
            open_funding: Some(LiquidityPositionOpenFunding {
                input_notes: vec![seller_funding_note],
                change_notes: vec![],
                authorization: seller_open_auth,
            }),
            output_notes: vec![],
            base_amount: 0,
            quote_amount: 0,
            lifecycle_authorization: None,
        },
        LiquidityPositionTransitionWitness {
            transition: buyer_open_transition,
            prior_position: None,
            output_position: Some(buyer_open.clone()),
            state_update: buyer_open_update,
            epoch,
            fill: None,
            open_funding: Some(LiquidityPositionOpenFunding {
                input_notes: vec![buyer_funding_note],
                change_notes: vec![],
                authorization: buyer_open_auth,
            }),
            output_notes: vec![],
            base_amount: 0,
            quote_amount: 0,
            lifecycle_authorization: None,
        },
        LiquidityPositionTransitionWitness {
            transition: seller_fill_transition,
            prior_position: Some(seller_open),
            output_position: Some(seller_filled),
            state_update: seller_fill_update,
            epoch,
            fill: Some(LiquidityPositionSettlementFill {
                market_context: market_context.clone(),
                position_side: OrderSide::Sell,
                filled_base_amount: fill_amount,
                clearing_price,
                price_base_scale: PRICE_SCALE_18,
            }),
            open_funding: None,
            output_notes: vec![],
            base_amount: 0,
            quote_amount: 0,
            lifecycle_authorization: None,
        },
        LiquidityPositionTransitionWitness {
            transition: buyer_fill_transition,
            prior_position: Some(buyer_open),
            output_position: Some(buyer_filled),
            state_update: buyer_fill_update,
            epoch,
            fill: Some(LiquidityPositionSettlementFill {
                market_context,
                position_side: OrderSide::Buy,
                filled_base_amount: fill_amount,
                clearing_price,
                price_base_scale: PRICE_SCALE_18,
            }),
            open_funding: None,
            output_notes: vec![],
            base_amount: 0,
            quote_amount: 0,
            lifecycle_authorization: None,
        },
    ];
    let arguments = build_stwo_serialized_input(&witness)?;
    let published_artifacts = PublishedBatchArtifacts {
        transcript,
        output_bundle,
        liquidity_provider_attribution_bundle: None,
        settlement_witness: witness,
        published_at_unix_ms: now_unix_ms(),
        settled_at_unix_ms: None,
        settlement_transaction_hash: None,
        settlement_contract_address: None,
        order_execution_reports: vec![],
        transcript_shape: None,
    };
    let admission_root = auction_admission_root(
        &published_artifacts.settlement_witness,
        &auction_order_witnesses,
    )?;
    let auction_result_arguments = build_auction_result_serialized_input(
        &published_artifacts.settlement_witness,
        &auction_order_witnesses,
    )?;
    Ok(SmokeFixture {
        arguments,
        auction_result_arguments: Some(auction_result_arguments),
        auction_order_witnesses,
        published_artifacts,
        funding_activations: vec![seller_activation, buyer_activation],
        admission_root: Some(admission_root),
    })
}

fn build_lp_oracle_skew_smoke_arguments() -> Result<Vec<String>, Box<dyn Error>> {
    let pair_id = PairId("ETH/USDC".into());
    let base_asset_id = AssetId("ETH".into());
    let quote_asset_id = AssetId("USDC".into());
    let clearing_price = 2_500 * USDC_SCALE_6;
    let fill_amount = PRICE_SCALE_18 / 20;
    let oracle_guard = Some(LiquidityPositionOracleGuard {
        oracle_id: "pragma:ETH/USD".into(),
        max_staleness_ms: 30_000,
        max_divergence_bps: 100,
    });
    let market_context = LiquidityPositionMarketContext {
        epoch: 40,
        observed_at_unix_ms: 1_789_000_000_000,
        current_time_unix_ms: 1_789_000_010_000,
        reference_price: clearing_price,
        confirmation_price: Some(2_501 * USDC_SCALE_6),
        price_base_scale: PRICE_SCALE_18,
    };
    let policy = LiquidityPositionCurvePolicy {
        kind: LiquidityPositionCurveKind::InventorySkewed,
        band_count: 5,
        spread_bps: 0,
        target_base_ratio_bps: 5_000,
        inventory_skew_bps: 250,
        max_price_deviation_bps: 100,
    };
    let seller_position = position_with_policy(
        PositionSpec {
            position_id: "0x7201".into(),
            owner_authority: "0x8201".into(),
            base_reserve: 5 * PRICE_SCALE_18,
            quote_reserve: 12_500 * USDC_SCALE_6,
            blinding: "0x9201".into(),
            metadata_commitment: "0xa201".into(),
            pair_id: pair_id.clone(),
            base_asset_id: base_asset_id.clone(),
            quote_asset_id: quote_asset_id.clone(),
            price_lower_bound: 2_350 * USDC_SCALE_6,
            price_upper_bound: 2_650 * USDC_SCALE_6,
            max_fill_base_per_batch: PRICE_SCALE_18 / 2,
            opened_epoch: 1,
            expiry_epoch: 90,
        },
        policy.clone(),
        oracle_guard.clone(),
    );
    let buyer_position = position_with_policy(
        PositionSpec {
            position_id: "0x7202".into(),
            owner_authority: "0x8202".into(),
            base_reserve: 5 * PRICE_SCALE_18,
            quote_reserve: 12_500 * USDC_SCALE_6,
            blinding: "0x9202".into(),
            metadata_commitment: "0xa202".into(),
            pair_id: pair_id.clone(),
            base_asset_id: base_asset_id.clone(),
            quote_asset_id: quote_asset_id.clone(),
            price_lower_bound: 2_350 * USDC_SCALE_6,
            price_upper_bound: 2_650 * USDC_SCALE_6,
            max_fill_base_per_batch: PRICE_SCALE_18 / 2,
            opened_epoch: 1,
            expiry_epoch: 90,
        },
        policy,
        oracle_guard,
    );
    let mut position_state =
        LiquidityPositionState::from_positions(&[seller_position.clone(), buyer_position.clone()])?;
    let prior_position_root = position_state.root()?;
    let mut transitions = Vec::new();
    let mut witnesses = Vec::new();
    append_fill_transition(
        &mut position_state,
        &mut transitions,
        &mut witnesses,
        seller_position,
        OrderSide::Sell,
        fill_amount,
        &market_context,
        clearing_price,
        "0x9301".into(),
    )?;
    append_fill_transition(
        &mut position_state,
        &mut transitions,
        &mut witnesses,
        buyer_position,
        OrderSide::Buy,
        fill_amount,
        &market_context,
        clearing_price,
        "0x9302".into(),
    )?;
    let batch_id = BatchId("stwo-smoke-lp-oracle-skew-eth-usdc-40".into());
    let output_bundle = OutputCiphertextBundle::from_ciphertexts(
        batch_id.clone(),
        "stwo-smoke-lp-oracle-skew-da",
        vec![],
    )?;
    let output_recovery_dummy_commitments = output_bundle
        .ciphertexts
        .iter()
        .map(|ciphertext| {
            ciphertext
                .recovery
                .as_ref()
                .map(|recovery| recovery.commitment.clone())
                .ok_or("padded LP oracle-skew smoke ciphertext is missing its recovery commitment")
        })
        .collect::<Result<Vec<_>, _>>()?;

    let transcript = SettlementTranscript {
        batch_id,
        pair_id,
        batch_epoch: market_context.epoch,
        order_commitment_root: "0x111".into(),
        encrypted_order_set_commitment: "0x222".into(),
        prior_note_root: "0x0".into(),
        prior_nullifier_root: "0x0".into(),
        prior_renewal_root: "0x0".into(),
        prior_fee_root: "0x0".into(),
        prior_liquidity_position_root: prior_position_root,
        new_nullifier_root: "0x0".into(),
        new_renewal_root: "0x0".into(),
        new_liquidity_position_root: position_state.root()?,
        clearing_price,
        price_base_scale: PRICE_SCALE_18,
        taker_fee_bps: 0,
        relay_fee_bps: 0,
        protocol_fee_recipient: "0x4010".into(),
        relay_fee_recipient: "0x4020".into(),
        matched_orders: vec![],
        consumed_inputs: vec![],
        renewal_child_uses: vec![],
        liquidity_position_transitions: transitions,
        fees: vec![],
        output_notes: vec![],
        output_note_preimages: vec![],
        output_recovery_records: vec![],
        output_recovery_dummy_commitments,
        output_ciphertext_bundle_ref: output_bundle.bundle_commitment,
    };
    let mut witness = build_settlement_witness(
        &transcript,
        transcript.pair_id.clone(),
        "0x999",
        base_asset_id,
        quote_asset_id,
        vec![],
    )?;
    witness.liquidity_position_witnesses = witnesses;

    Ok(build_stwo_serialized_input(&witness)?)
}

fn owner_authority_from_private_key(private_key: &str) -> Result<String, Box<dyn Error>> {
    Ok(liquidity_position_private_authority(private_key)?)
}

struct NoteSpec {
    asset_id: AssetId,
    amount: u128,
    owner_authority: String,
    owner_public_key: String,
    blinding: String,
    nonce: u64,
    metadata_commitment: String,
}

fn sample_owner_note(spec: NoteSpec) -> Note {
    Note {
        asset_id: spec.asset_id,
        amount: spec.amount,
        owner_public_key: spec.owner_public_key,
        spend_authority: spec.owner_authority.clone(),
        withdraw_authority: spec.owner_authority,
        blinding: spec.blinding,
        nonce: spec.nonce,
        metadata_commitment: spec.metadata_commitment,
    }
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

fn funding_activation_from_note(note: &Note) -> Result<SmokeFundingActivation, Box<dyn Error>> {
    let note_commitment = note.commitment()?;
    let deposit_root = deposit_root_from_note(note)?;
    let funding_commitment = funding_commitment_for_deposit(&note_commitment.0, &deposit_root)?;
    let encrypted_note_activation =
        encrypted_note_activation_commitment(&note_commitment.0, &deposit_root)?;
    Ok(SmokeFundingActivation {
        funding_commitment,
        deposit_root,
        encrypted_note_activation,
        note_commitment: note_commitment.0,
    })
}

fn live_smoke_fee_config() -> Result<SmokeSettlementFeeConfig, Box<dyn Error>> {
    Ok(SmokeSettlementFeeConfig {
        taker_fee_bps: env_u16("ZYLITH_SMOKE_TAKER_FEE_BPS", 0)?,
        relay_fee_bps: env_u16("ZYLITH_SMOKE_RELAY_FEE_BPS", 0)?,
        protocol_fee_recipient: env::var("ZYLITH_SMOKE_PROTOCOL_FEE_RECIPIENT")
            .unwrap_or_else(|_| "0x4010".into()),
        relay_fee_recipient: env::var("ZYLITH_SMOKE_RELAY_FEE_RECIPIENT")
            .unwrap_or_else(|_| "0x4020".into()),
    })
}

fn live_smoke_auction_verifier_address() -> String {
    env::var("ZYLITH_SMOKE_AUCTION_VERIFIER_ADDRESS")
        .ok()
        .or_else(|| env::var("ZYLITH_AUCTION_VERIFIER_ADDRESS").ok())
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| "0x999".into())
}

fn env_u16(name: &str, default: u16) -> Result<u16, Box<dyn Error>> {
    match env::var(name) {
        Ok(value) => Ok(value.parse()?),
        Err(env::VarError::NotPresent) => Ok(default),
        Err(error) => Err(error.into()),
    }
}

#[allow(clippy::too_many_arguments)]
fn append_fill_transition(
    position_state: &mut LiquidityPositionState,
    transitions: &mut Vec<LiquidityPositionRootTransition>,
    witnesses: &mut Vec<LiquidityPositionTransitionWitness>,
    prior_position: PrivateLiquidityPosition,
    position_side: OrderSide,
    filled_base_amount: u128,
    market_context: &LiquidityPositionMarketContext,
    clearing_price: u128,
    next_blinding: String,
) -> Result<(), Box<dyn Error>> {
    let (output_position, _) = apply_liquidity_position_fill(
        &prior_position,
        position_side.clone(),
        filled_base_amount,
        clearing_price,
        market_context.price_base_scale,
        &next_blinding,
    )?;
    let (_, _, state_update) = position_state.replace(&prior_position, &output_position)?;
    let transition = liquidity_position_root_transition(
        LiquidityPositionTransitionKind::Update,
        Some(&prior_position),
        Some(&output_position),
    )?;
    transitions.push(transition.clone());
    witnesses.push(LiquidityPositionTransitionWitness {
        transition,
        prior_position: Some(prior_position),
        output_position: Some(output_position),
        state_update,
        epoch: market_context.epoch,
        fill: Some(LiquidityPositionSettlementFill {
            market_context: market_context.clone(),
            position_side,
            filled_base_amount,
            clearing_price,
            price_base_scale: market_context.price_base_scale,
        }),
        open_funding: None,
        output_notes: vec![],
        base_amount: 0,
        quote_amount: 0,
        lifecycle_authorization: None,
    });
    Ok(())
}

struct PositionSpec {
    position_id: String,
    owner_authority: String,
    base_reserve: u128,
    quote_reserve: u128,
    blinding: String,
    metadata_commitment: String,
    pair_id: PairId,
    base_asset_id: AssetId,
    quote_asset_id: AssetId,
    price_lower_bound: u128,
    price_upper_bound: u128,
    max_fill_base_per_batch: u128,
    opened_epoch: u64,
    expiry_epoch: u64,
}

fn position_with_policy(
    spec: PositionSpec,
    curve_policy: LiquidityPositionCurvePolicy,
    oracle_guard: Option<LiquidityPositionOracleGuard>,
) -> PrivateLiquidityPosition {
    PrivateLiquidityPosition {
        version: LIQUIDITY_POSITION_VERSION,
        position_id: spec.position_id,
        backing: LiquidityPositionBacking::PrivateReserve,
        status: LiquidityPositionStatus::Active,
        pair_id: spec.pair_id,
        base_asset_id: spec.base_asset_id,
        quote_asset_id: spec.quote_asset_id,
        owner_authority: spec.owner_authority,
        base_reserve: spec.base_reserve,
        quote_reserve: spec.quote_reserve,
        price_lower_bound: spec.price_lower_bound,
        price_upper_bound: spec.price_upper_bound,
        max_fill_base_per_batch: spec.max_fill_base_per_batch,
        curve_policy,
        oracle_guard,
        rotation_policy: LiquidityPositionRotationPolicy {
            max_price_rotation_bps: 0,
            max_depth_rotation_bps: 0,
            skip_epoch_bps: 0,
        },
        opened_epoch: spec.opened_epoch,
        expiry_epoch: spec.expiry_epoch,
        blinding: spec.blinding,
        metadata_commitment: spec.metadata_commitment,
    }
}

fn sample_position_for_pair(spec: PositionSpec) -> PrivateLiquidityPosition {
    PrivateLiquidityPosition {
        version: LIQUIDITY_POSITION_VERSION,
        position_id: spec.position_id,
        backing: LiquidityPositionBacking::PrivateReserve,
        status: LiquidityPositionStatus::Active,
        pair_id: spec.pair_id,
        base_asset_id: spec.base_asset_id,
        quote_asset_id: spec.quote_asset_id,
        owner_authority: spec.owner_authority,
        base_reserve: spec.base_reserve,
        quote_reserve: spec.quote_reserve,
        price_lower_bound: spec.price_lower_bound,
        price_upper_bound: spec.price_upper_bound,
        max_fill_base_per_batch: spec.max_fill_base_per_batch,
        curve_policy: LiquidityPositionCurvePolicy {
            kind: LiquidityPositionCurveKind::StaticRange,
            band_count: 3,
            spread_bps: 0,
            target_base_ratio_bps: 5_000,
            inventory_skew_bps: 0,
            max_price_deviation_bps: 0,
        },
        oracle_guard: None,
        rotation_policy: LiquidityPositionRotationPolicy {
            max_price_rotation_bps: 0,
            max_depth_rotation_bps: 0,
            skip_epoch_bps: 0,
        },
        opened_epoch: spec.opened_epoch,
        expiry_epoch: spec.expiry_epoch,
        blinding: spec.blinding,
        metadata_commitment: spec.metadata_commitment,
    }
}

fn sample_position(
    position_id: &str,
    owner_authority: &str,
    base_reserve: u128,
    quote_reserve: u128,
    blinding: &str,
    metadata_commitment: &str,
) -> PrivateLiquidityPosition {
    PrivateLiquidityPosition {
        version: LIQUIDITY_POSITION_VERSION,
        position_id: position_id.into(),
        backing: LiquidityPositionBacking::PrivateReserve,
        status: LiquidityPositionStatus::Active,
        pair_id: PairId("STRK/USDC".into()),
        base_asset_id: AssetId("STRK".into()),
        quote_asset_id: AssetId("USDC".into()),
        owner_authority: owner_authority.into(),
        base_reserve,
        quote_reserve,
        price_lower_bound: 300 * PRICE_SCALE_18,
        price_upper_bound: 400 * PRICE_SCALE_18,
        max_fill_base_per_batch: 200,
        curve_policy: LiquidityPositionCurvePolicy {
            kind: LiquidityPositionCurveKind::StaticRange,
            band_count: 3,
            spread_bps: 0,
            target_base_ratio_bps: 5_000,
            inventory_skew_bps: 0,
            max_price_deviation_bps: 0,
        },
        oracle_guard: None,
        rotation_policy: LiquidityPositionRotationPolicy {
            max_price_rotation_bps: 0,
            max_depth_rotation_bps: 0,
            skip_epoch_bps: 0,
        },
        opened_epoch: 1,
        expiry_epoch: 20,
        blinding: blinding.into(),
        metadata_commitment: metadata_commitment.into(),
    }
}

struct MultiPairFillSpec<'a> {
    commitment: &'a str,
    pair: &'a str,
    base: &'a str,
    quote: &'a str,
    base_amount: u128,
    quote_amount: u128,
    limit_price: u128,
    fee_amount: u128,
}

fn multi_pair_buy(spec: MultiPairFillSpec<'_>) -> MultiPairFill {
    multi_pair_fill(spec, OrderSide::Buy)
}

fn multi_pair_sell(spec: MultiPairFillSpec<'_>) -> MultiPairFill {
    multi_pair_fill(spec, OrderSide::Sell)
}

fn multi_pair_fill(spec: MultiPairFillSpec<'_>, side: OrderSide) -> MultiPairFill {
    MultiPairFill {
        order_commitment: OrderCommitment(spec.commitment.into()),
        pair_id: PairId(spec.pair.into()),
        base_asset_id: AssetId(spec.base.into()),
        quote_asset_id: AssetId(spec.quote.into()),
        side,
        submitted_base_amount: spec.base_amount,
        min_fill_base_amount: 1,
        limit_price: spec.limit_price,
        price_base_scale: 1,
        filled_base_amount: spec.base_amount,
        quote_amount: spec.quote_amount,
        fee_amount: spec.fee_amount,
    }
}

fn multi_pair_user_delta(
    commitment: &str,
    asset: &str,
    amount: u128,
    direction: MultiPairAssetDeltaDirection,
) -> MultiPairAssetDelta {
    multi_pair_delta(
        commitment,
        asset,
        amount,
        direction,
        MultiPairAssetDeltaSource::User,
    )
}

fn multi_pair_fee_delta(
    commitment: &str,
    asset: &str,
    amount: u128,
    direction: MultiPairAssetDeltaDirection,
) -> MultiPairAssetDelta {
    multi_pair_delta(
        commitment,
        asset,
        amount,
        direction,
        MultiPairAssetDeltaSource::Fee,
    )
}

fn multi_pair_liquidity_delta(
    commitment: &str,
    asset: &str,
    amount: u128,
    direction: MultiPairAssetDeltaDirection,
) -> MultiPairAssetDelta {
    multi_pair_delta(
        commitment,
        asset,
        amount,
        direction,
        MultiPairAssetDeltaSource::LiquidityPosition,
    )
}

fn multi_pair_delta(
    commitment: &str,
    asset: &str,
    amount: u128,
    direction: MultiPairAssetDeltaDirection,
    source: MultiPairAssetDeltaSource,
) -> MultiPairAssetDelta {
    MultiPairAssetDelta {
        asset_id: AssetId(asset.into()),
        amount,
        direction,
        source,
        source_commitment: Some(commitment.into()),
    }
}

#[cfg(test)]
mod tests {
    use super::{
        build_lp_fill_smoke_arguments, build_lp_lifecycle_smoke_arguments,
        build_lp_open_fill_e2e_smoke_fixture, build_lp_oracle_skew_smoke_arguments,
        build_lp_soak_smoke_arguments, build_lp_user_fill_auction_result_smoke_arguments,
        build_multi_pair_smoke_arguments, build_smoke_arguments,
    };

    #[test]
    fn smoke_arguments_are_a_single_length_prefixed_settlement_span() {
        let arguments = build_smoke_arguments().expect("smoke arguments");
        let payload_len = usize::from_str_radix(arguments[0].trim_start_matches("0x"), 16)
            .expect("payload length");
        assert_eq!(payload_len, arguments.len() - 1);
        assert_eq!(arguments[1], "0x1");
    }

    #[test]
    fn lp_fill_smoke_arguments_are_a_single_length_prefixed_settlement_span() {
        let arguments = build_lp_fill_smoke_arguments().expect("LP-fill smoke arguments");
        let payload_len = usize::from_str_radix(arguments[0].trim_start_matches("0x"), 16)
            .expect("payload length");
        assert_eq!(payload_len, arguments.len() - 1);
        assert_eq!(arguments[1], "0x1");
    }

    #[test]
    fn lp_user_fill_smoke_arguments_are_a_single_length_prefixed_auction_result_span() {
        let arguments = build_lp_user_fill_auction_result_smoke_arguments()
            .expect("LP user-fill auction-result smoke arguments");
        let payload_len = usize::from_str_radix(arguments[0].trim_start_matches("0x"), 16)
            .expect("payload length");
        assert_eq!(payload_len, arguments.len() - 1);
        assert_eq!(arguments[1], "0x4");
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
    fn lp_soak_smoke_arguments_are_a_single_length_prefixed_settlement_span() {
        let arguments = build_lp_soak_smoke_arguments().expect("LP-soak smoke arguments");
        let payload_len = usize::from_str_radix(arguments[0].trim_start_matches("0x"), 16)
            .expect("payload length");
        assert_eq!(payload_len, arguments.len() - 1);
        assert_eq!(arguments[1], "0x1");
        assert!(
            arguments.len()
                > build_lp_fill_smoke_arguments()
                    .expect("LP-fill smoke arguments")
                    .len()
        );
    }

    #[test]
    fn lp_lifecycle_smoke_arguments_are_a_single_length_prefixed_settlement_span() {
        let arguments = build_lp_lifecycle_smoke_arguments().expect("LP-lifecycle smoke arguments");
        let payload_len = usize::from_str_radix(arguments[0].trim_start_matches("0x"), 16)
            .expect("payload length");
        assert_eq!(payload_len, arguments.len() - 1);
        assert_eq!(arguments[1], "0x1");
    }

    #[test]
    fn lp_open_fill_e2e_fixture_exports_prover_records_and_deposit_activations() {
        let fixture = build_lp_open_fill_e2e_smoke_fixture().expect("LP E2E smoke fixture");
        let payload_len = usize::from_str_radix(fixture.arguments[0].trim_start_matches("0x"), 16)
            .expect("payload length");
        assert_eq!(payload_len, fixture.arguments.len() - 1);
        assert_eq!(fixture.arguments[1], "0x1");
        assert_eq!(fixture.funding_activations.len(), 2);
        assert_eq!(
            fixture
                .published_artifacts
                .transcript
                .prior_liquidity_position_root,
            "0x0"
        );
        assert_eq!(
            fixture
                .published_artifacts
                .settlement_witness
                .liquidity_position_witnesses
                .len(),
            4
        );
    }

    #[test]
    fn lp_oracle_skew_smoke_arguments_are_a_single_length_prefixed_settlement_span() {
        let arguments =
            build_lp_oracle_skew_smoke_arguments().expect("LP oracle-skew smoke arguments");
        let payload_len = usize::from_str_radix(arguments[0].trim_start_matches("0x"), 16)
            .expect("payload length");
        assert_eq!(payload_len, arguments.len() - 1);
        assert_eq!(arguments[1], "0x1");
    }
}
