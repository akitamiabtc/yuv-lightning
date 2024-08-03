// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

use crate::ln::channelmanager;
use crate::ln::functional_test_utils::new_test_pixel;
use crate::routing::gossip::{NetworkGraph, NodeAlias, P2PGossipSync};
use crate::ln::features::{ChannelFeatures, NodeFeatures};
use crate::ln::msgs::{ChannelAnnouncement, ChannelUpdate, MAX_VALUE_MSAT, NodeAnnouncement, RoutingMessageHandler, SocketAddress, UnsignedChannelAnnouncement, UnsignedChannelUpdate, UnsignedNodeAnnouncement};
use crate::sign::EntropySource;
use crate::util::config::UserConfig;
use crate::util::test_utils::{self, TestChainSource};
use crate::util::ser::Writeable;

use bitcoin::blockdata::constants::ChainHash;
use bitcoin::hashes::sha256d::Hash as Sha256dHash;
use bitcoin::hashes::Hash;
use bitcoin::hashes::hex::FromHex;
use bitcoin::network::constants::Network;
use bitcoin::secp256k1::{PublicKey,SecretKey};
use bitcoin::secp256k1::{Secp256k1, All};
use yuv_pixels::{Chroma, Pixel};
use crate::ln::chan_utils::make_funding_redeemscript;

#[allow(unused)]
use crate::prelude::*;
use crate::sync::{self, Arc};

use crate::routing::gossip::NodeId;

use crate::util::test_utils as ln_test_utils;

use super::router::PaymentParameters;

// Using the same keys for LN and BTC ids
pub(crate) fn add_channel(
	gossip_sync: &P2PGossipSync<Arc<NetworkGraph<Arc<test_utils::TestLogger>>>, Arc<test_utils::TestChainSource>, Arc<test_utils::TestLogger>>,
	secp_ctx: &Secp256k1<All>, node_1_privkey: &SecretKey, node_2_privkey: &SecretKey, features: ChannelFeatures, short_channel_id: u64
) {
	add_channel_internal(gossip_sync, secp_ctx, node_1_privkey, node_2_privkey, features, short_channel_id, None, None);
}

pub(super) fn add_channel_internal(
	gossip_sync: &P2PGossipSync<Arc<NetworkGraph<Arc<test_utils::TestLogger>>>, Arc<test_utils::TestChainSource>, Arc<test_utils::TestLogger>>,
	secp_ctx: &Secp256k1<All>,
	node_1_privkey: &SecretKey,
	node_2_privkey: &SecretKey,
	features: ChannelFeatures,
	short_channel_id: u64,
	yuv_pixel: Option<Pixel>,
	chain_source: Option<Arc<test_utils::TestChainSource>>,
) {
	let node_pk_1 = &PublicKey::from_secret_key(&secp_ctx, node_1_privkey);
	let node_pk_2 = &PublicKey::from_secret_key(&secp_ctx, node_2_privkey);

	let node_id_1 = NodeId::from_pubkey(node_pk_1);
	let node_id_2 = NodeId::from_pubkey(node_pk_2);

	if let Some(chain_source) = chain_source.as_ref() {
		let expected_script =
			make_funding_redeemscript(&node_pk_1, &node_pk_2, yuv_pixel.as_ref()).to_v0_p2wsh();

		chain_source.set_txout(expected_script, MAX_VALUE_MSAT / 1000);
	}

	if let Some(yuv_pixel) = yuv_pixel {
		chain_source.as_ref().map(|chain_source| chain_source.set_yuv_pixel(yuv_pixel));
	}

	let unsigned_announcement = UnsignedChannelAnnouncement {
		features,
		chain_hash: ChainHash::using_genesis_block(Network::Testnet),
		short_channel_id,
		node_id_1,
		node_id_2,
		bitcoin_key_1: node_id_1,
		bitcoin_key_2: node_id_2,
		is_yuv_payments_supported: yuv_pixel.is_some(),
		excess_data: Vec::new(),
	};

	let msghash = hash_to_message!(&Sha256dHash::hash(&unsigned_announcement.encode()[..])[..]);
	let valid_announcement = ChannelAnnouncement {
		node_signature_1: secp_ctx.sign_ecdsa(&msghash, node_1_privkey),
		node_signature_2: secp_ctx.sign_ecdsa(&msghash, node_2_privkey),
		bitcoin_signature_1: secp_ctx.sign_ecdsa(&msghash, node_1_privkey),
		bitcoin_signature_2: secp_ctx.sign_ecdsa(&msghash, node_2_privkey),
		contents: unsigned_announcement.clone(),
	};
	match gossip_sync.handle_channel_announcement(&valid_announcement) {
		Ok(res) => assert!(res),
		Err(err) => panic!("{:?}", err),
	};
}

pub(crate) fn add_or_update_node(
	gossip_sync: &P2PGossipSync<Arc<NetworkGraph<Arc<test_utils::TestLogger>>>, Arc<test_utils::TestChainSource>, Arc<test_utils::TestLogger>>,
	secp_ctx: &Secp256k1<All>, node_privkey: &SecretKey, features: NodeFeatures, timestamp: u32
) {
	let node_id = NodeId::from_pubkey(&PublicKey::from_secret_key(&secp_ctx, node_privkey));
	let unsigned_announcement = UnsignedNodeAnnouncement {
		features,
		timestamp,
		node_id,
		rgb: [0; 3],
		alias: NodeAlias([0; 32]),
		addresses: vec![SocketAddress::TcpIpV4 { addr: [127, 0, 0, 1], port: 1000 }],
		excess_address_data: Vec::new(),
		excess_data: Vec::new(),
	};
	let msghash = hash_to_message!(&Sha256dHash::hash(&unsigned_announcement.encode()[..])[..]);
	let valid_announcement = NodeAnnouncement {
		signature: secp_ctx.sign_ecdsa(&msghash, node_privkey),
		contents: unsigned_announcement.clone()
	};

	match gossip_sync.handle_node_announcement(&valid_announcement) {
		Ok(_) => (),
		Err(_) => panic!()
	};
}

pub(crate) fn update_channel(
	gossip_sync: &P2PGossipSync<Arc<NetworkGraph<Arc<test_utils::TestLogger>>>, Arc<test_utils::TestChainSource>, Arc<test_utils::TestLogger>>,
	secp_ctx: &Secp256k1<All>, node_privkey: &SecretKey, update: UnsignedChannelUpdate
) {
	let msghash = hash_to_message!(&Sha256dHash::hash(&update.encode()[..])[..]);
	let valid_channel_update = ChannelUpdate {
		signature: secp_ctx.sign_ecdsa(&msghash, node_privkey),
		contents: update.clone()
	};

	match gossip_sync.handle_channel_update(&valid_channel_update) {
		Ok(res) => assert!(res),
		Err(err) => panic!("{:?}", err)
	};
}

pub(super) fn get_nodes(secp_ctx: &Secp256k1<All>) -> (SecretKey, PublicKey, Vec<SecretKey>, Vec<PublicKey>) {
	let privkeys: Vec<SecretKey> = (2..22).map(|i| {
		SecretKey::from_slice(&<Vec<u8>>::from_hex(&format!("{:02x}", i).repeat(32)).unwrap()[..]).unwrap()
	}).collect();

	let pubkeys = privkeys.iter().map(|secret| PublicKey::from_secret_key(&secp_ctx, secret)).collect();

	let our_privkey = SecretKey::from_slice(&<Vec<u8>>::from_hex(&"01".repeat(32)).unwrap()[..]).unwrap();
	let our_id = PublicKey::from_secret_key(&secp_ctx, &our_privkey);

	(our_privkey, our_id, privkeys, pubkeys)
}

pub(super) fn id_to_feature_flags(id: u8) -> Vec<u8> {
	// Set the feature flags to the id'th odd (ie non-required) feature bit so that we can
	// test for it later.
	let idx = (id - 1) * 2 + 1;
	if idx > 8*3 {
		vec![1 << (idx - 8*3), 0, 0, 0]
	} else if idx > 8*2 {
		vec![1 << (idx - 8*2), 0, 0]
	} else if idx > 8*1 {
		vec![1 << (idx - 8*1), 0]
	} else {
		vec![1 << idx]
	}
}

pub(super) fn build_line_graph() -> (
	Secp256k1<All>, sync::Arc<NetworkGraph<Arc<test_utils::TestLogger>>>,
	P2PGossipSync<sync::Arc<NetworkGraph<Arc<test_utils::TestLogger>>>, sync::Arc<test_utils::TestChainSource>, sync::Arc<test_utils::TestLogger>>,
	sync::Arc<test_utils::TestChainSource>, sync::Arc<test_utils::TestLogger>,
) {
	let secp_ctx = Secp256k1::new();
	let logger = Arc::new(test_utils::TestLogger::new());
	let chain_monitor = Arc::new(test_utils::TestChainSource::new(Network::Testnet));
	let network_graph = Arc::new(NetworkGraph::new(Network::Testnet, Arc::clone(&logger)));
	let gossip_sync = P2PGossipSync::new(Arc::clone(&network_graph), None, Arc::clone(&logger));

	// Build network from our_id to node 19:
	// our_id -1(1)2- node0 -1(2)2- node1 - ... - node19
	let (our_privkey, _, privkeys, _) = get_nodes(&secp_ctx);

	for (idx, (cur_privkey, next_privkey)) in core::iter::once(&our_privkey)
		.chain(privkeys.iter()).zip(privkeys.iter()).enumerate() {
			let cur_short_channel_id = (idx as u64) + 1;
			add_channel(&gossip_sync, &secp_ctx, &cur_privkey, &next_privkey,
				ChannelFeatures::from_le_bytes(id_to_feature_flags(1)), cur_short_channel_id);
			update_channel(&gossip_sync, &secp_ctx, &cur_privkey, UnsignedChannelUpdate {
				chain_hash: ChainHash::using_genesis_block(Network::Testnet),
				short_channel_id: cur_short_channel_id,
				timestamp: idx as u32,
				flags: 0,
				cltv_expiry_delta: 0,
				htlc_minimum_msat: 0,
				htlc_maximum_msat: MAX_VALUE_MSAT,
				fee_base_msat: 0,
				fee_proportional_millionths: 0,
				excess_data: Vec::new(),
				htlc_maximum_yuv: None,
			});
			update_channel(&gossip_sync, &secp_ctx, &next_privkey, UnsignedChannelUpdate {
				chain_hash: ChainHash::using_genesis_block(Network::Testnet),
				short_channel_id: cur_short_channel_id,
				timestamp: (idx as u32)+1,
				flags: 1,
				cltv_expiry_delta: 0,
				htlc_minimum_msat: 0,
				htlc_maximum_msat: MAX_VALUE_MSAT,
				fee_base_msat: 0,
				fee_proportional_millionths: 0,
				excess_data: Vec::new(),
				htlc_maximum_yuv: None,
			});
			add_or_update_node(&gossip_sync, &secp_ctx, &next_privkey,
				NodeFeatures::from_le_bytes(id_to_feature_flags(1)), 0);
		}

	(secp_ctx, network_graph, gossip_sync, chain_monitor, logger)
}

pub(super) fn build_graph() -> (
	Secp256k1<All>,
	sync::Arc<NetworkGraph<Arc<test_utils::TestLogger>>>,
	P2PGossipSync<sync::Arc<NetworkGraph<Arc<test_utils::TestLogger>>>, sync::Arc<test_utils::TestChainSource>, sync::Arc<test_utils::TestLogger>>,
	sync::Arc<test_utils::TestChainSource>,
	sync::Arc<test_utils::TestLogger>,
) {
	build_graph_internal(None, false)
}

pub(super) fn build_graph_with_yuv(chroma: Chroma, use_chain_source: bool) -> (
	Secp256k1<All>,
	sync::Arc<NetworkGraph<Arc<test_utils::TestLogger>>>,
	P2PGossipSync<sync::Arc<NetworkGraph<Arc<test_utils::TestLogger>>>, sync::Arc<test_utils::TestChainSource>, sync::Arc<test_utils::TestLogger>>,
	sync::Arc<test_utils::TestChainSource>,
	sync::Arc<test_utils::TestLogger>,
) {
	build_graph_internal(Some(chroma), use_chain_source)
}

pub(super) fn build_graph_internal(chroma: Option<Chroma>, use_chain_source: bool) -> (
	Secp256k1<All>,
	sync::Arc<NetworkGraph<Arc<test_utils::TestLogger>>>,
	P2PGossipSync<sync::Arc<NetworkGraph<Arc<test_utils::TestLogger>>>, sync::Arc<test_utils::TestChainSource>, sync::Arc<test_utils::TestLogger>>,
	sync::Arc<test_utils::TestChainSource>,
	sync::Arc<test_utils::TestLogger>,
) {
	let secp_ctx = Secp256k1::new();
	let logger = Arc::new(test_utils::TestLogger::new());
	let chain_monitor = Arc::new(test_utils::TestChainSource::new(Network::Testnet));

	let yuv_pixel = chroma.map(|chroma| {
		let yuv_pixel = Pixel::new(u128::MAX, chroma);
		chain_monitor.set_yuv_pixel(yuv_pixel);
		yuv_pixel
	});

	let chain_source = if use_chain_source {
		Some(chain_monitor.clone())
	} else { None };

	let network_graph = Arc::new(NetworkGraph::new(Network::Testnet, Arc::clone(&logger)));
	let gossip_sync = P2PGossipSync::new(Arc::clone(&network_graph), chain_source, Arc::clone(&logger));
	// Build network from our_id to node6:
	//
	//        -1(1)2-  node0  -1(3)2-
	//       /                       \
	// our_id -1(12)2- node7 -1(13)2--- node2
	//       \                       /
	//        -1(2)2-  node1  -1(4)2-
	//
	//
	// chan1  1-to-2: disabled
	// chan1  2-to-1: enabled, 0 fee
	//
	// chan2  1-to-2: enabled, ignored fee
	// chan2  2-to-1: enabled, 0 fee
	//
	// chan3  1-to-2: enabled, 0 fee
	// chan3  2-to-1: enabled, 100 msat fee
	//
	// chan4  1-to-2: enabled, 100% fee
	// chan4  2-to-1: enabled, 0 fee
	//
	// chan12 1-to-2: enabled, ignored fee
	// chan12 2-to-1: enabled, 0 fee
	//
	// chan13 1-to-2: enabled, 200% fee
	// chan13 2-to-1: enabled, 0 fee
	//
	//
	//       -1(5)2- node3 -1(8)2--
	//       |         2          |
	//       |       (11)         |
	//      /          1           \
	// node2--1(6)2- node4 -1(9)2--- node6 (not in global route map)
	//      \                      /
	//       -1(7)2- node5 -1(10)2-
	//
	// Channels 5, 8, 9 and 10 are private channels.
	//
	// chan5  1-to-2: enabled, 100 msat fee
	// chan5  2-to-1: enabled, 0 fee
	//
	// chan6  1-to-2: enabled, 0 fee
	// chan6  2-to-1: enabled, 0 fee
	//
	// chan7  1-to-2: enabled, 100% fee
	// chan7  2-to-1: enabled, 0 fee
	//
	// chan8  1-to-2: enabled, variable fee (0 then 1000 msat)
	// chan8  2-to-1: enabled, 0 fee
	//
	// chan9  1-to-2: enabled, 1001 msat fee
	// chan9  2-to-1: enabled, 0 fee
	//
	// chan10 1-to-2: enabled, 0 fee
	// chan10 2-to-1: enabled, 0 fee
	//
	// chan11 1-to-2: enabled, 0 fee
	// chan11 2-to-1: enabled, 0 fee

	let (our_privkey, _, privkeys, _) = get_nodes(&secp_ctx);

	const HTLC_MAXIMUM_YUV: u128 = u128::MAX;

	add_channel_internal(&gossip_sync, &secp_ctx, &our_privkey, &privkeys[0], ChannelFeatures::from_le_bytes(id_to_feature_flags(1)), 1, yuv_pixel, Some(chain_monitor.clone()));
	update_channel(&gossip_sync, &secp_ctx, &privkeys[0], UnsignedChannelUpdate {
		chain_hash: ChainHash::using_genesis_block(Network::Testnet),
		short_channel_id: 1,
		timestamp: 1,
		flags: 1,
		cltv_expiry_delta: 0,
		htlc_minimum_msat: 0,
		htlc_maximum_msat: MAX_VALUE_MSAT,
		fee_base_msat: 0,
		fee_proportional_millionths: 0,
		excess_data: Vec::new(),
		htlc_maximum_yuv: chroma.map(|_| HTLC_MAXIMUM_YUV),
	});

	add_or_update_node(&gossip_sync, &secp_ctx, &privkeys[0], NodeFeatures::from_le_bytes(id_to_feature_flags(1)), 0);

	add_channel_internal(&gossip_sync, &secp_ctx, &our_privkey, &privkeys[1], ChannelFeatures::from_le_bytes(id_to_feature_flags(2)), 2, yuv_pixel, Some(chain_monitor.clone()));
	update_channel(&gossip_sync, &secp_ctx, &our_privkey, UnsignedChannelUpdate {
		chain_hash: ChainHash::using_genesis_block(Network::Testnet),
		short_channel_id: 2,
		timestamp: 1,
		flags: 0,
		cltv_expiry_delta: (5 << 4) | 3,
		htlc_minimum_msat: 0,
		htlc_maximum_msat: MAX_VALUE_MSAT,
		fee_base_msat: u32::max_value(),
		fee_proportional_millionths: u32::max_value(),
		excess_data: Vec::new(),
		htlc_maximum_yuv: chroma.map(|_| HTLC_MAXIMUM_YUV),
	});
	update_channel(&gossip_sync, &secp_ctx, &privkeys[1], UnsignedChannelUpdate {
		chain_hash: ChainHash::using_genesis_block(Network::Testnet),
		short_channel_id: 2,
		timestamp: 1,
		flags: 1,
		cltv_expiry_delta: 0,
		htlc_minimum_msat: 0,
		htlc_maximum_msat: MAX_VALUE_MSAT,
		fee_base_msat: 0,
		fee_proportional_millionths: 0,
		excess_data: Vec::new(),
		htlc_maximum_yuv: chroma.map(|_| HTLC_MAXIMUM_YUV),
	});

	add_or_update_node(&gossip_sync, &secp_ctx, &privkeys[1], NodeFeatures::from_le_bytes(id_to_feature_flags(2)), 0);

	add_channel_internal(&gossip_sync, &secp_ctx, &our_privkey, &privkeys[7], ChannelFeatures::from_le_bytes(id_to_feature_flags(12)), 12, yuv_pixel, Some(chain_monitor.clone()));
	update_channel(&gossip_sync, &secp_ctx, &our_privkey, UnsignedChannelUpdate {
		chain_hash: ChainHash::using_genesis_block(Network::Testnet),
		short_channel_id: 12,
		timestamp: 1,
		flags: 0,
		cltv_expiry_delta: (5 << 4) | 3,
		htlc_minimum_msat: 0,
		htlc_maximum_msat: MAX_VALUE_MSAT,
		fee_base_msat: u32::max_value(),
		fee_proportional_millionths: u32::max_value(),
		excess_data: Vec::new(),
		htlc_maximum_yuv: chroma.map(|_| HTLC_MAXIMUM_YUV),
	});
	update_channel(&gossip_sync, &secp_ctx, &privkeys[7], UnsignedChannelUpdate {
		chain_hash: ChainHash::using_genesis_block(Network::Testnet),
		short_channel_id: 12,
		timestamp: 1,
		flags: 1,
		cltv_expiry_delta: 0,
		htlc_minimum_msat: 0,
		htlc_maximum_msat: MAX_VALUE_MSAT,
		fee_base_msat: 0,
		fee_proportional_millionths: 0,
		excess_data: Vec::new(),
		htlc_maximum_yuv: chroma.map(|_| HTLC_MAXIMUM_YUV),
	});

	add_or_update_node(&gossip_sync, &secp_ctx, &privkeys[7], NodeFeatures::from_le_bytes(id_to_feature_flags(8)), 0);

	add_channel_internal(&gossip_sync, &secp_ctx, &privkeys[0], &privkeys[2], ChannelFeatures::from_le_bytes(id_to_feature_flags(3)), 3, yuv_pixel, Some(chain_monitor.clone()));
	update_channel(&gossip_sync, &secp_ctx, &privkeys[0], UnsignedChannelUpdate {
		chain_hash: ChainHash::using_genesis_block(Network::Testnet),
		short_channel_id: 3,
		timestamp: 1,
		flags: 0,
		cltv_expiry_delta: (3 << 4) | 1,
		htlc_minimum_msat: 0,
		htlc_maximum_msat: MAX_VALUE_MSAT,
		fee_base_msat: 0,
		fee_proportional_millionths: 0,
		excess_data: Vec::new(),
		htlc_maximum_yuv: chroma.map(|_| HTLC_MAXIMUM_YUV),
	});
	update_channel(&gossip_sync, &secp_ctx, &privkeys[2], UnsignedChannelUpdate {
		chain_hash: ChainHash::using_genesis_block(Network::Testnet),
		short_channel_id: 3,
		timestamp: 1,
		flags: 1,
		cltv_expiry_delta: (3 << 4) | 2,
		htlc_minimum_msat: 0,
		htlc_maximum_msat: MAX_VALUE_MSAT,
		fee_base_msat: 100,
		fee_proportional_millionths: 0,
		excess_data: Vec::new(),
		htlc_maximum_yuv: chroma.map(|_| HTLC_MAXIMUM_YUV),
	});

	add_channel_internal(&gossip_sync, &secp_ctx, &privkeys[1], &privkeys[2], ChannelFeatures::from_le_bytes(id_to_feature_flags(4)), 4, yuv_pixel, Some(chain_monitor.clone()));
	update_channel(&gossip_sync, &secp_ctx, &privkeys[1], UnsignedChannelUpdate {
		chain_hash: ChainHash::using_genesis_block(Network::Testnet),
		short_channel_id: 4,
		timestamp: 1,
		flags: 0,
		cltv_expiry_delta: (4 << 4) | 1,
		htlc_minimum_msat: 0,
		htlc_maximum_msat: MAX_VALUE_MSAT,
		fee_base_msat: 0,
		fee_proportional_millionths: 1000000,
		excess_data: Vec::new(),
		htlc_maximum_yuv: chroma.map(|_| HTLC_MAXIMUM_YUV),
	});
	update_channel(&gossip_sync, &secp_ctx, &privkeys[2], UnsignedChannelUpdate {
		chain_hash: ChainHash::using_genesis_block(Network::Testnet),
		short_channel_id: 4,
		timestamp: 1,
		flags: 1,
		cltv_expiry_delta: (4 << 4) | 2,
		htlc_minimum_msat: 0,
		htlc_maximum_msat: MAX_VALUE_MSAT,
		fee_base_msat: 0,
		fee_proportional_millionths: 0,
		excess_data: Vec::new(),
		htlc_maximum_yuv: chroma.map(|_| HTLC_MAXIMUM_YUV),
	});

	add_channel_internal(&gossip_sync, &secp_ctx, &privkeys[7], &privkeys[2], ChannelFeatures::from_le_bytes(id_to_feature_flags(13)), 13, yuv_pixel, Some(chain_monitor.clone()));
	update_channel(&gossip_sync, &secp_ctx, &privkeys[7], UnsignedChannelUpdate {
		chain_hash: ChainHash::using_genesis_block(Network::Testnet),
		short_channel_id: 13,
		timestamp: 1,
		flags: 0,
		cltv_expiry_delta: (13 << 4) | 1,
		htlc_minimum_msat: 0,
		htlc_maximum_msat: MAX_VALUE_MSAT,
		fee_base_msat: 0,
		fee_proportional_millionths: 2000000,
		excess_data: Vec::new(),
		htlc_maximum_yuv: chroma.map(|_| HTLC_MAXIMUM_YUV),
	});
	update_channel(&gossip_sync, &secp_ctx, &privkeys[2], UnsignedChannelUpdate {
		chain_hash: ChainHash::using_genesis_block(Network::Testnet),
		short_channel_id: 13,
		timestamp: 1,
		flags: 1,
		cltv_expiry_delta: (13 << 4) | 2,
		htlc_minimum_msat: 0,
		htlc_maximum_msat: MAX_VALUE_MSAT,
		fee_base_msat: 0,
		fee_proportional_millionths: 0,
		excess_data: Vec::new(),
		htlc_maximum_yuv: chroma.map(|_| HTLC_MAXIMUM_YUV),
	});

	add_or_update_node(&gossip_sync, &secp_ctx, &privkeys[2], NodeFeatures::from_le_bytes(id_to_feature_flags(3)), 0);

	add_channel_internal(&gossip_sync, &secp_ctx, &privkeys[2], &privkeys[4], ChannelFeatures::from_le_bytes(id_to_feature_flags(6)), 6, yuv_pixel, Some(chain_monitor.clone()));
	update_channel(&gossip_sync, &secp_ctx, &privkeys[2], UnsignedChannelUpdate {
		chain_hash: ChainHash::using_genesis_block(Network::Testnet),
		short_channel_id: 6,
		timestamp: 1,
		flags: 0,
		cltv_expiry_delta: (6 << 4) | 1,
		htlc_minimum_msat: 0,
		htlc_maximum_msat: MAX_VALUE_MSAT,
		fee_base_msat: 0,
		fee_proportional_millionths: 0,
		excess_data: Vec::new(),
		htlc_maximum_yuv: chroma.map(|_| HTLC_MAXIMUM_YUV),
	});
	update_channel(&gossip_sync, &secp_ctx, &privkeys[4], UnsignedChannelUpdate {
		chain_hash: ChainHash::using_genesis_block(Network::Testnet),
		short_channel_id: 6,
		timestamp: 1,
		flags: 1,
		cltv_expiry_delta: (6 << 4) | 2,
		htlc_minimum_msat: 0,
		htlc_maximum_msat: MAX_VALUE_MSAT,
		fee_base_msat: 0,
		fee_proportional_millionths: 0,
		excess_data: Vec::new(),
		htlc_maximum_yuv: chroma.map(|_| HTLC_MAXIMUM_YUV),
	});

	add_channel_internal(&gossip_sync, &secp_ctx, &privkeys[4], &privkeys[3], ChannelFeatures::from_le_bytes(id_to_feature_flags(11)), 11, yuv_pixel, Some(chain_monitor.clone()));
	update_channel(&gossip_sync, &secp_ctx, &privkeys[4], UnsignedChannelUpdate {
		chain_hash: ChainHash::using_genesis_block(Network::Testnet),
		short_channel_id: 11,
		timestamp: 1,
		flags: 0,
		cltv_expiry_delta: (11 << 4) | 1,
		htlc_minimum_msat: 0,
		htlc_maximum_msat: MAX_VALUE_MSAT,
		fee_base_msat: 0,
		fee_proportional_millionths: 0,
		excess_data: Vec::new(),
		htlc_maximum_yuv: chroma.map(|_| HTLC_MAXIMUM_YUV),
	});
	update_channel(&gossip_sync, &secp_ctx, &privkeys[3], UnsignedChannelUpdate {
		chain_hash: ChainHash::using_genesis_block(Network::Testnet),
		short_channel_id: 11,
		timestamp: 1,
		flags: 1,
		cltv_expiry_delta: (11 << 4) | 2,
		htlc_minimum_msat: 0,
		htlc_maximum_msat: MAX_VALUE_MSAT,
		fee_base_msat: 0,
		fee_proportional_millionths: 0,
		excess_data: Vec::new(),
		htlc_maximum_yuv: chroma.map(|_| HTLC_MAXIMUM_YUV),
	});

	add_or_update_node(&gossip_sync, &secp_ctx, &privkeys[4], NodeFeatures::from_le_bytes(id_to_feature_flags(5)), 0);

	add_or_update_node(&gossip_sync, &secp_ctx, &privkeys[3], NodeFeatures::from_le_bytes(id_to_feature_flags(4)), 0);

	add_channel_internal(&gossip_sync, &secp_ctx, &privkeys[2], &privkeys[5], ChannelFeatures::from_le_bytes(id_to_feature_flags(7)), 7, yuv_pixel, Some(chain_monitor.clone()));
	update_channel(&gossip_sync, &secp_ctx, &privkeys[2], UnsignedChannelUpdate {
		chain_hash: ChainHash::using_genesis_block(Network::Testnet),
		short_channel_id: 7,
		timestamp: 1,
		flags: 0,
		cltv_expiry_delta: (7 << 4) | 1,
		htlc_minimum_msat: 0,
		htlc_maximum_msat: MAX_VALUE_MSAT,
		fee_base_msat: 0,
		fee_proportional_millionths: 1000000,
		excess_data: Vec::new(),
		htlc_maximum_yuv: chroma.map(|_| HTLC_MAXIMUM_YUV),
	});
	update_channel(&gossip_sync, &secp_ctx, &privkeys[5], UnsignedChannelUpdate {
		chain_hash: ChainHash::using_genesis_block(Network::Testnet),
		short_channel_id: 7,
		timestamp: 1,
		flags: 1,
		cltv_expiry_delta: (7 << 4) | 2,
		htlc_minimum_msat: 0,
		htlc_maximum_msat: MAX_VALUE_MSAT,
		fee_base_msat: 0,
		fee_proportional_millionths: 0,
		excess_data: Vec::new(),
		htlc_maximum_yuv: chroma.map(|_| HTLC_MAXIMUM_YUV),
	});

	add_or_update_node(&gossip_sync, &secp_ctx, &privkeys[5], NodeFeatures::from_le_bytes(id_to_feature_flags(6)), 0);

	(secp_ctx, network_graph, gossip_sync, chain_monitor, logger)
}


pub(super) struct SetupYuvRoutingTestResult {
	pub(crate) pixel: Pixel,
	pub(crate) secp_ctx: Secp256k1<bitcoin::secp256k1::All>,
	pub(crate) network_graph: Arc<NetworkGraph<Arc<ln_test_utils::TestLogger>>>,
	pub(crate) gossip_sync: P2PGossipSync<Arc<NetworkGraph<Arc<ln_test_utils::TestLogger>>>, Arc<ln_test_utils::TestChainSource>, Arc<ln_test_utils::TestLogger>>,
	pub(crate) logger: Arc<ln_test_utils::TestLogger>,
	pub(crate) our_privkey: SecretKey, 
	pub(crate) our_id: PublicKey, 
	pub(crate) node_privkeys: Vec<SecretKey>, 
	pub(crate) random_seed_bytes: [u8; 32],
	pub(crate) scorer: ln_test_utils::TestScorer,
	pub(crate) payment_params: PaymentParameters,
	pub(crate) chain_source: Arc<TestChainSource>,
	pub(crate) nodes: Vec<PublicKey>,
}

pub(super) fn setup_simple_yuv_routing_test() -> SetupYuvRoutingTestResult {
    let test_pixel = new_test_pixel(Some(u128::MAX.into()), None, &Secp256k1::new());

    let (secp_ctx, network_graph, gossip_sync, chain_source, logger) = build_graph_with_yuv(test_pixel.chroma, true);
    let (our_privkey, our_id, privkeys, nodes) = get_nodes(&secp_ctx);
    let keys_manager = ln_test_utils::TestKeysInterface::new(&[0u8; 32], Network::Testnet);
    let random_seed_bytes = keys_manager.get_secure_random_bytes();
    let scorer = ln_test_utils::TestScorer::new();

    // Disable channels which we are not interested in, particulartl our->node1->node2	
    update_channel(&gossip_sync, &secp_ctx, &our_privkey, UnsignedChannelUpdate {
	    chain_hash: ChainHash::using_genesis_block(Network::Testnet),
	    short_channel_id: 2,
	    timestamp: 2,
	    flags: 2, // disable channel flag
	    cltv_expiry_delta: 0,
	    htlc_minimum_msat: 0,
	    htlc_maximum_msat: 0,
	    fee_base_msat: 0,
	    fee_proportional_millionths: 0,
	    excess_data: Vec::new(),
	    htlc_maximum_yuv: Some(0),
	});
    // Update liquidities, setting up path our->node1->noed2
    // Setting our----(1)-->node0 with 200 sats adn 2000 YUV.
    // And     node0--(3)-->node2 with 300 sats and 3000 YUV.
    update_channel(&gossip_sync, &secp_ctx, &our_privkey, UnsignedChannelUpdate {
	    chain_hash: ChainHash::using_genesis_block(Network::Testnet),
	    short_channel_id: 1,
	    timestamp: 2,
	    flags: 0,
	    cltv_expiry_delta: 0,
	    htlc_minimum_msat: 0,
	    htlc_maximum_msat: 200_000,
	    fee_base_msat: 0,
	    fee_proportional_millionths: 0,
	    excess_data: Vec::new(),
	    htlc_maximum_yuv: Some(3000),
    });
    update_channel(&gossip_sync, &secp_ctx, &privkeys[0], UnsignedChannelUpdate {
	    chain_hash: ChainHash::using_genesis_block(Network::Testnet),
	    short_channel_id: 3,
	    timestamp: 2,
	    flags: 0,
	    cltv_expiry_delta: 0,
	    htlc_minimum_msat: 0,
	    htlc_maximum_msat: 200_000,
	    fee_base_msat: 0,
	    fee_proportional_millionths: 0,
	    excess_data: Vec::new(),
	    htlc_maximum_yuv: Some(2000),
    });
    // Remove fee from 13 channel
    update_channel(&gossip_sync, &secp_ctx, &privkeys[7], UnsignedChannelUpdate {
	    chain_hash: ChainHash::using_genesis_block(Network::Testnet),
	    short_channel_id: 13,
	    timestamp: 2,
	    flags: 0,
	    cltv_expiry_delta: 0,
	    htlc_minimum_msat: 0,
	    htlc_maximum_msat: MAX_VALUE_MSAT,
	    fee_base_msat: 0,
	    fee_proportional_millionths: 0,
	    excess_data: Vec::new(),
	    htlc_maximum_yuv: Some(u128::MAX),
    });
	
    // Constructring payment parameters to `node2` with YUV payment feature
    let config = UserConfig {
			    support_yuv_payments: true,
			    ..Default::default()
		    };
    let payment_params = PaymentParameters::from_node_id(nodes[2], 42)
			    .with_bolt11_features(channelmanager::provided_bolt11_invoice_features(&config))
			    .unwrap();

    SetupYuvRoutingTestResult {
		pixel: test_pixel, secp_ctx, network_graph,
		gossip_sync, logger, our_privkey, our_id,
		node_privkeys: privkeys,
		random_seed_bytes, scorer, payment_params,
		chain_source, nodes,
    }
}

pub(super) fn setup_simple_yuv_mpp_test() -> SetupYuvRoutingTestResult {
	let res = setup_simple_yuv_routing_test();
	
	// Add maximum limits for "node7", so algorithm would split payment through
	// two pathes using "node0" and "node7".
	update_channel(&res.gossip_sync, &res.secp_ctx, &res.node_privkeys[7], UnsignedChannelUpdate {
		chain_hash: ChainHash::using_genesis_block(Network::Testnet),
		short_channel_id: 13,
		timestamp: 3,
		flags: 0,
		cltv_expiry_delta: 0,
		htlc_minimum_msat: 0,
		htlc_maximum_msat: 300_000,
		fee_base_msat: 0,
		fee_proportional_millionths: 0,
		excess_data: Vec::new(),
		htlc_maximum_yuv: Some(3000),
	});
	update_channel(&res.gossip_sync, &res.secp_ctx, &res.our_privkey, UnsignedChannelUpdate {
		chain_hash: ChainHash::using_genesis_block(Network::Testnet),
		short_channel_id: 12,
		timestamp: 3,
		flags: 0,
		cltv_expiry_delta: 0,
		htlc_minimum_msat: 0,
		htlc_maximum_msat: 300_000,
		fee_base_msat: 0,
		fee_proportional_millionths: 0,
		excess_data: Vec::new(),
		htlc_maximum_yuv: Some(3000),
	});

	res
}

struct UpdateChannelCapacityYuv {
	node_id: usize,
	timestamp: u32,
	short_channel_id: u64,
	htlc_maximum_msat: u64,
	htlc_maximum_yuv: u128,
}

fn update_channel_capacity_with_yuv(res: &SetupYuvRoutingTestResult, req: UpdateChannelCapacityYuv) {
	update_channel(&res.gossip_sync, &res.secp_ctx, &res.node_privkeys[req.node_id], UnsignedChannelUpdate {
		chain_hash: ChainHash::using_genesis_block(Network::Testnet),
		short_channel_id: req.short_channel_id, 
		timestamp: req.timestamp,
		flags: 0, // this make it public
		cltv_expiry_delta: 0, 
		htlc_minimum_msat: 0,
		htlc_maximum_msat: req.htlc_maximum_msat,
		fee_base_msat: 0,
		fee_proportional_millionths: 0,
		htlc_maximum_yuv: Some(req.htlc_maximum_yuv), // Add YUV support here
		excess_data:  Vec::new(),
	});
}

/// Make channel 5 public, and make 5,2,4,6,11 channels support
/// YUV and set node 3 as target this time.
pub(super) fn setup_long_yuv_mpp_test() -> SetupYuvRoutingTestResult {
	let res = setup_simple_yuv_mpp_test();

	// Make channel 5 public with YUV, sats and YUV capacity set to 
	add_channel_internal(&res.gossip_sync, &res.secp_ctx, &res.node_privkeys[2],
		&res.node_privkeys[3], ChannelFeatures::from_le_bytes(id_to_feature_flags(5)),
		5, Some(res.pixel), Some(res.chain_source.clone()));
	update_channel_capacity_with_yuv(&res, UpdateChannelCapacityYuv {
		node_id: 2,
		timestamp: 3,
		short_channel_id: 5,
		htlc_maximum_msat: 500_000,
		htlc_maximum_yuv: 5000,
	});

	// Update channel 2 with limited YUVs capacity
	update_channel(&res.gossip_sync, &res.secp_ctx, &res.our_privkey, UnsignedChannelUpdate {
		chain_hash: ChainHash::using_genesis_block(Network::Testnet),
		short_channel_id: 2, 
		timestamp: 3,
		flags: 0, // this make it public
		cltv_expiry_delta: 0, 
		htlc_minimum_msat: 0,
		htlc_maximum_msat: 500_000,
		fee_base_msat: 0,
		fee_proportional_millionths: 0,
		htlc_maximum_yuv: Some(4000), // Add YUV support here
		excess_data:  Vec::new(),
	});
	// Update channel 4 to remove proportional fee:
	update_channel_capacity_with_yuv(&res, UpdateChannelCapacityYuv {
		node_id: 1,
		timestamp: 3,
		short_channel_id: 4,
		htlc_maximum_msat: 500_000,
		htlc_maximum_yuv: 4000,
	});

	// Update channel 6 with new YUV limits
	update_channel_capacity_with_yuv(&res, UpdateChannelCapacityYuv {
		node_id: 2,
		timestamp: 3,
		short_channel_id: 6,
		htlc_maximum_msat: 500_000,
		htlc_maximum_yuv: 5000,
	});
	// The same for 11
	update_channel_capacity_with_yuv(&res, UpdateChannelCapacityYuv {
		node_id: 4,
		timestamp: 3,
		short_channel_id: 11,
		htlc_maximum_msat: 500_000,
		htlc_maximum_yuv: 5000,
	});

	res
}

