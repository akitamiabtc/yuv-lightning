// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Convenient utilities for paying Lightning invoices.

use crate::Bolt11Invoice;
use bitcoin::hashes::Hash;

use lightning::ln::types::PaymentHash;
use lightning::ln::channelmanager::RecipientOnionFields;
use lightning::routing::router::{PaymentParameters, RouteParameters};

use lightning::chain;
use lightning::chain::chaininterface::{BroadcasterInterface, FeeEstimator, YuvBroadcaster};
use lightning::sign::{NodeSigner, SignerProvider, EntropySource};
use lightning::ln::PaymentHash;
use lightning::ln::channelmanager::{AChannelManager, ChannelManager, PaymentId, Retry, RetryableSendFailure, RecipientOnionFields, ProbeSendFailure};
use lightning::routing::router::{DEFAULT_YUV_MAX_PATH_COUNT, PaymentParameters, RouteParameters, Router};
use lightning::util::logger::Logger;

use core::fmt::Debug;
use core::ops::Deref;
use core::time::Duration;

/// Pays the given [`Bolt11Invoice`], retrying if needed based on [`Retry`].
///
/// Prior to paying, you must ensure that the [`Bolt11Invoice::payment_hash`] is unique and the
/// same [`PaymentHash`] has never been paid before.
///
/// Will always succeed unless the invoice has an amount specified, in which case
/// [`payment_parameters_from_invoice`] should be used.
///
/// [`ChannelManager::send_payment`]: lightning::ln::channelmanager::ChannelManager::send_payment
/// [`ChannelManager::send_preflight_probes`]: lightning::ln::channelmanager::ChannelManager::send_preflight_probes
pub fn payment_parameters_from_zero_amount_invoice(invoice: &Bolt11Invoice, amount_msat: u64)
-> Result<(PaymentHash, RecipientOnionFields, RouteParameters), ()> {
	if invoice.amount_milli_satoshis().is_some() {
		Err(())
	} else {
		Ok(params_from_invoice(invoice, amount_msat))
	}
}

/// Builds the necessary parameters to pay or pre-flight probe the given [`Bolt11Invoice`] using
/// [`ChannelManager::send_payment`] or [`ChannelManager::send_preflight_probes`].
///
/// Prior to paying, you must ensure that the [`Bolt11Invoice::payment_hash`] is unique and the
/// same [`PaymentHash`] has never been paid before.
///
/// Will always succeed unless the invoice has no amount specified, in which case
/// [`payment_parameters_from_zero_amount_invoice`] should be used.
///
/// [`ChannelManager::send_payment`]: lightning::ln::channelmanager::ChannelManager::send_payment
/// [`ChannelManager::send_preflight_probes`]: lightning::ln::channelmanager::ChannelManager::send_preflight_probes
pub fn payment_parameters_from_invoice(invoice: &Bolt11Invoice)
-> Result<(PaymentHash, RecipientOnionFields, RouteParameters), ()> {
	if let Some(amount_msat) = invoice.amount_milli_satoshis() {
		Ok(params_from_invoice(invoice, amount_msat))
	} else {
		Err(())
	}
}

fn params_from_invoice(invoice: &Bolt11Invoice, amount_msat: u64)
-> (PaymentHash, RecipientOnionFields, RouteParameters) {
	let payment_hash = PaymentHash((*invoice.payment_hash()).to_byte_array());

	let mut recipient_onion = RecipientOnionFields::secret_only(*invoice.payment_secret());
	recipient_onion.payment_metadata = invoice.payment_metadata().map(|v| v.clone());

	let mut payment_params = PaymentParameters::from_node_id(
			invoice.recover_payee_pub_key(),
			invoice.min_final_cltv_expiry_delta() as u32
		)
		.with_route_hints(invoice.route_hints()).unwrap();
	if let Some(expiry) = invoice.expires_at() {
		payment_params = payment_params.with_expiry_time(expiry.as_secs());
	}
	if let Some(features) = invoice.features() {
		payment_params = payment_params.with_bolt11_features(features.clone()).unwrap();
	}
	let route_params = match invoice.yuv_pixel() {
		Some(yuv_pixel) => {
			payment_params = payment_params.with_max_path_count(DEFAULT_YUV_MAX_PATH_COUNT);
			RouteParameters::from_payment_params_and_value(payment_params, amount_msats)
				.with_yuv(yuv_pixel)
		}
		None => RouteParameters::from_payment_params_and_value(payment_params, amount_msats)
	};

	let route_params = RouteParameters::from_payment_params_and_value(payment_params, amount_msat);

	channelmanager.get_cm().send_preflight_probes(route_params, liquidity_limit_multiplier)
		.map_err(ProbingError::Sending)
}

/// Sends payment probes over all paths of a route that would be used to pay the given zero-value
/// invoice using the given amount.
///
/// See [`ChannelManager::send_preflight_probes`] for more information.
pub fn preflight_probe_zero_value_invoice<C: AChannelManager>(
	invoice: &Bolt11Invoice, amount_msat: u64, channelmanager: &C,
	liquidity_limit_multiplier: Option<u64>,
) -> Result<Vec<(PaymentHash, PaymentId)>, ProbingError>
{
	if invoice.amount_milli_satoshis().is_some() {
		return Err(ProbingError::Invoice("amount unexpected"));
	}

	let mut payment_params = PaymentParameters::from_node_id(
		invoice.recover_payee_pub_key(),
		invoice.min_final_cltv_expiry_delta() as u32,
	)
	.with_expiry_time(expiry_time_from_unix_epoch(invoice).as_secs())
	.with_route_hints(invoice.route_hints())
	.unwrap();

	if let Some(features) = invoice.features() {
		payment_params = payment_params.with_bolt11_features(features.clone()).unwrap();
	}
	let route_params = RouteParameters::from_payment_params_and_value(payment_params, amount_msat);

	channelmanager.get_cm().send_preflight_probes(route_params, liquidity_limit_multiplier)
		.map_err(ProbingError::Sending)
}

fn expiry_time_from_unix_epoch(invoice: &Bolt11Invoice) -> Duration {
	invoice.signed_invoice.raw_invoice.data.timestamp.0 + invoice.expiry_time()
}

/// An error that may occur when making a payment.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PaymentError {
	/// An error resulting from the provided [`Bolt11Invoice`] or payment hash.
	Invoice(&'static str),
	/// An error occurring when sending a payment.
	Sending(RetryableSendFailure),
}

/// An error that may occur when sending a payment probe.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProbingError {
	/// An error resulting from the provided [`Bolt11Invoice`].
	Invoice(&'static str),
	/// An error occurring when sending a payment probe.
	Sending(ProbeSendFailure),
}

/// A trait defining behavior of a [`Bolt11Invoice`] payer.
///
/// Useful for unit testing internal methods.
trait Payer {
	/// Sends a payment over the Lightning Network using the given [`Route`].
	///
	/// [`Route`]: lightning::routing::router::Route
	fn send_payment(
		&self, payment_hash: PaymentHash, recipient_onion: RecipientOnionFields,
		payment_id: PaymentId, route_params: RouteParameters, retry_strategy: Retry
	) -> Result<(), PaymentError>;
}

impl<M: Deref, T: Deref, YT: Deref, ES: Deref, NS: Deref, SP: Deref, F: Deref, R: Deref, L: Deref> Payer for ChannelManager<M, T, YT, ES, NS, SP, F, R, L>
where
		M::Target: chain::Watch<<SP::Target as SignerProvider>::Signer>,
		T::Target: BroadcasterInterface,
		YT::Target: YuvBroadcaster,
		ES::Target: EntropySource,
		NS::Target: NodeSigner,
		SP::Target: SignerProvider,
		F::Target: FeeEstimator,
		R::Target: Router,
		L::Target: Logger,
{
	fn send_payment(
		&self, payment_hash: PaymentHash, recipient_onion: RecipientOnionFields,
		payment_id: PaymentId, route_params: RouteParameters, retry_strategy: Retry
	) -> Result<(), PaymentError> {
		self.send_payment(payment_hash, recipient_onion, payment_id, route_params, retry_strategy)
			.map_err(PaymentError::Sending)
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::{InvoiceBuilder, Currency};
	use bitcoin_hashes::sha256::Hash as Sha256;
	use lightning::events::{Event, PaymentPurpose};
	use lightning::ln::msgs::ChannelMessageHandler;
	use lightning::ln::{PaymentPreimage, PaymentSecret};
	use lightning::ln::functional_test_utils::*;
	use secp256k1::{SecretKey, Secp256k1};
	use std::collections::VecDeque;
	use std::time::{SystemTime, Duration};
	use yuv_pixels::{Luma, Pixel};
	use crate::utils::create_yuv_invoice_from_channelmanager_and_duration_since_epoch;

	struct TestPayer {
		expectations: core::cell::RefCell<VecDeque<Amount>>,
		yuv_expectations: core::cell::RefCell<VecDeque<Pixel>>,
	}

	impl TestPayer {
		fn new() -> Self {
			Self {
				expectations: core::cell::RefCell::new(VecDeque::new()),
				yuv_expectations: core::cell::RefCell::new(VecDeque::new()),
			}
		}

		fn expect_send(self, value_msat: Amount) -> Self {
			self.expectations.borrow_mut().push_back(value_msat);
			self
		}

		fn expect_yuv_send(self, yuv_pixel: Pixel) -> Self {
			self.yuv_expectations.borrow_mut().push_back(yuv_pixel);
			self
		}

		fn check_value_msats(&self, actual_value_msats: Amount) {
			let expected_value_msats = self.expectations.borrow_mut().pop_front();
			if let Some(expected_value_msats) = expected_value_msats {
				assert_eq!(actual_value_msats, expected_value_msats);
			} else {
				panic!("Unexpected amount: {:?}", actual_value_msats);
			}
		}
	}

	#[derive(Clone, Debug, PartialEq, Eq)]
	struct Amount(u64); // msat

	impl Payer for TestPayer {
		fn send_payment(
			&self, _payment_hash: PaymentHash, _recipient_onion: RecipientOnionFields,
			_payment_id: PaymentId, route_params: RouteParameters, _retry_strategy: Retry
		) -> Result<(), PaymentError> {
			self.check_value_msats(Amount(route_params.final_value_msat));
			Ok(())
		}
	}

	impl Drop for TestPayer {
		fn drop(&mut self) {
			if std::thread::panicking() {
				return;
			}

			if !self.expectations.borrow().is_empty() {
				panic!("Unsatisfied payment expectations: {:?}", self.expectations.borrow());
			}
		}
	}

	fn duration_since_epoch() -> Duration {
		#[cfg(feature = "std")]
		let duration_since_epoch =
			SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap();
		#[cfg(not(feature = "std"))]
		let duration_since_epoch = Duration::from_secs(1234567);
		duration_since_epoch
	}

	#[test]
	fn invoice_test() {
		let payment_hash = Sha256::hash(&[0; 32]);
		let private_key = SecretKey::from_slice(&[42; 32]).unwrap();
		let secp_ctx = Secp256k1::new();
		let public_key = PublicKey::from_secret_key(&secp_ctx, &private_key);

		let invoice = InvoiceBuilder::new(Currency::Bitcoin)
			.description("test".into())
			.payment_hash(payment_hash)
			.payment_secret(PaymentSecret([0; 32]))
			.duration_since_epoch(duration_since_epoch())
			.min_final_cltv_expiry_delta(144)
			.amount_milli_satoshis(128)
			.build_signed(|hash| {
				secp_ctx.sign_ecdsa_recoverable(hash, &private_key)
			})
			.unwrap();

		assert!(payment_parameters_from_zero_amount_invoice(&invoice, 42).is_err());

		let (hash, onion, params) = payment_parameters_from_invoice(&invoice).unwrap();
		assert_eq!(&hash.0[..], &payment_hash[..]);
		assert_eq!(onion.payment_secret, Some(PaymentSecret([0; 32])));
		assert_eq!(params.final_value_msat, 128);
		match params.payment_params.payee {
			Payee::Clear { node_id, .. } => {
				assert_eq!(node_id, public_key);
			},
			_ => panic!(),
		}
	}

	fn yuv_invoice(payment_preimage: PaymentPreimage) -> Bolt11Invoice {
		let payment_hash = Sha256::hash(&payment_preimage.0);
		let private_key = SecretKey::from_slice(&[42; 32]).unwrap();

		InvoiceBuilder::new(Currency::Bitcoin)
			.description("test".into())
			.payment_hash(payment_hash)
			.payment_secret(PaymentSecret([0; 32]))
			.duration_since_epoch(duration_since_epoch())
			.min_final_cltv_expiry_delta(144)
			.amount_milli_satoshis(128)
			.yuv_pixel(new_test_pixel(None, None, &secp256k1::Secp256k1::new()))
			.build_signed(|hash| {
				Secp256k1::new().sign_ecdsa_recoverable(hash, &private_key)
			})
			.unwrap()
	}

	fn zero_value_invoice(payment_preimage: PaymentPreimage) -> Bolt11Invoice {
		let payment_hash = Sha256::hash(&payment_preimage.0);
		let private_key = SecretKey::from_slice(&[42; 32]).unwrap();
		let secp_ctx = Secp256k1::new();
		let public_key = PublicKey::from_secret_key(&secp_ctx, &private_key);

		let invoice = InvoiceBuilder::new(Currency::Bitcoin)
			.description("test".into())
			.payment_hash(payment_hash)
			.payment_secret(PaymentSecret([0; 32]))
			.duration_since_epoch(duration_since_epoch())
			.min_final_cltv_expiry_delta(144)
			.build_signed(|hash| {
				secp_ctx.sign_ecdsa_recoverable(hash, &private_key)
			})
		.unwrap();

		assert!(payment_parameters_from_invoice(&invoice).is_err());

		let payer = TestPayer::new().expect_send(Amount(final_value_msat));
		pay_invoice_using_amount(&invoice, final_value_msat, payment_id, Retry::Attempts(0), &payer).unwrap();
	}

	#[test]
	fn pays_zero_value_invoice() {
		let payment_id = PaymentId([42; 32]);
		let payment_preimage = PaymentPreimage([1; 32]);
		let invoice = zero_value_invoice(payment_preimage);
		let amt_msat = 10_000;

		let payer = TestPayer::new().expect_send(Amount(amt_msat));
		pay_invoice_using_amount(&invoice, amt_msat, payment_id, Retry::Attempts(0), &payer).unwrap();
	}

	#[test]
	fn pays_yuv_invoice() {
		let payment_id = PaymentId([42; 32]);
		let payment_preimage = PaymentPreimage([1; 32]);
		let invoice = yuv_invoice(payment_preimage);
		let final_value_msat = invoice.amount_milli_satoshis().unwrap();
		let final_pixel = invoice.yuv_pixel().unwrap();

		let payer = TestPayer::new()
			.expect_send(Amount(final_value_msat))
			.expect_yuv_send(final_pixel);
		pay_invoice_using_amount(
			&invoice, final_value_msat, payment_id, Retry::Attempts(0), &payer,
		).unwrap();
	}

	#[test]
	fn fails_paying_zero_value_invoice_with_amount() {
		let chanmon_cfgs = create_chanmon_cfgs(1);
		let node_cfgs = create_node_cfgs(1, &chanmon_cfgs);
		let node_chanmgrs = create_node_chanmgrs(1, &node_cfgs, &[None]);
		let nodes = create_network(1, &node_cfgs, &node_chanmgrs);

		let payment_preimage = PaymentPreimage([1; 32]);
		let invoice = invoice(payment_preimage);
		let amt_msat = 10_000;

		match pay_zero_value_invoice(&invoice, amt_msat, Retry::Attempts(0), nodes[0].node) {
			Err(PaymentError::Invoice("amount unexpected")) => {},
			_ => panic!()
		}
	}

	#[test]
	#[cfg(feature = "std")]
	fn payment_metadata_end_to_end() {
		use lightning::events::Event;
		use lightning::ln::channelmanager::{Retry, PaymentId};
		use lightning::ln::msgs::ChannelMessageHandler;
		use lightning::ln::functional_test_utils::*;
		// Test that a payment metadata read from an invoice passed to `pay_invoice` makes it all
		// the way out through the `PaymentClaimable` event.
		let chanmon_cfgs = create_chanmon_cfgs(2);
		let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
		let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
		let nodes = create_network(2, &node_cfgs, &node_chanmgrs);
		create_announced_chan_between_nodes(&nodes, 0, 1);

		let payment_metadata = vec![42, 43, 44, 45, 46, 47, 48, 49, 42];

		let (payment_hash, payment_secret) =
			nodes[1].node.create_inbound_payment(None, 7200, None).unwrap();

		let invoice = InvoiceBuilder::new(Currency::Bitcoin)
			.description("test".into())
			.payment_hash(Sha256::from_slice(&payment_hash.0).unwrap())
			.payment_secret(payment_secret)
			.current_timestamp()
			.min_final_cltv_expiry_delta(144)
			.amount_milli_satoshis(50_000)
			.payment_metadata(payment_metadata.clone())
			.build_signed(|hash| {
				Secp256k1::new().sign_ecdsa_recoverable(hash,
					&nodes[1].keys_manager.backing.get_node_secret_key())
			})
			.unwrap();

		let (hash, onion, params) = payment_parameters_from_invoice(&invoice).unwrap();
		nodes[0].node.send_payment(hash, onion, PaymentId(hash.0), params, Retry::Attempts(0)).unwrap();
		check_added_monitors(&nodes[0], 1);
		let send_event = SendEvent::from_node(&nodes[0]);
		nodes[1].node.handle_update_add_htlc(&nodes[0].node.get_our_node_id(), &send_event.msgs[0]);
		commitment_signed_dance!(nodes[1], nodes[0], &send_event.commitment_msg, false);

		expect_pending_htlcs_forwardable!(nodes[1]);

		let mut events = nodes[1].node.get_and_clear_pending_events();
		assert_eq!(events.len(), 1);
		match events.pop().unwrap() {
			Event::PaymentClaimable { onion_fields, .. } => {
				assert_eq!(Some(payment_metadata), onion_fields.unwrap().payment_metadata);
			},
			_ => panic!("Unexpected event")
		}
	}

	#[test]
	#[cfg(feature = "std")]
	fn test_yuv_invoice() {
		let mut node_cfg_with_yuv_support = test_default_channel_config();
		node_cfg_with_yuv_support.support_yuv_payments = true;

		let chanmon_cfgs = create_chanmon_cfgs(2);
		let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
		let node_chanmgrs = create_node_chanmgrs(
			2, &node_cfgs, &[Some(node_cfg_with_yuv_support), Some(node_cfg_with_yuv_support)],
		);
		let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

		let funding_sat_amount = 100_000;
		let funding_yuv_amount = 100;

		let secp_ctx = Secp256k1::new();
		let funding_yuv_pixel = new_test_pixel(Some(Luma::from(funding_yuv_amount)), None, &secp_ctx);

		let _ = create_chan_with_yuv(&nodes, 0, 1, funding_sat_amount, 0, funding_yuv_pixel);

		let duration = SystemTime::now()
			.duration_since(SystemTime::UNIX_EPOCH)
			.expect("for the foreseeable future this shouldn't happen");

		let invoice = create_yuv_invoice_from_channelmanager_and_duration_since_epoch(
			nodes[1].node,
			nodes[1].keys_manager,
			nodes[1].logger,
			Currency::BitcoinTestnet,
			Some(5_000_000),
			"test".to_string(),
			duration,
			 100,
			None,
			Pixel::new(50, funding_yuv_pixel.chroma),
		).unwrap();

		pay_invoice(&invoice, Retry::Attempts(0), nodes[0].node).unwrap();
		check_added_monitors(&nodes[0], 1);
		let send_event = SendEvent::from_node(&nodes[0]);
		nodes[1].node.handle_update_add_htlc(&nodes[0].node.get_our_node_id(), &send_event.msgs[0]);
		commitment_signed_dance!(nodes[1], nodes[0], &send_event.commitment_msg, false);

		expect_pending_htlcs_forwardable!(nodes[1]);

		let mut events = nodes[1].node.get_and_clear_pending_events();
		assert_eq!(events.len(), 1);
		let Event::PaymentClaimable{ purpose: PaymentPurpose::InvoicePayment {
			payment_preimage: Some(_), ..
		}, .. } = events.pop().unwrap() else {
			panic!("Unexpected event")
		};
	}
}
