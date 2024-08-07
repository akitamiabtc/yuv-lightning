# 0.3.1+lightning-0.0.123 - Aug 03, 2024

## Changes

* Remove the `yuv_pixel_proofs` TLV field from the `FundingCreated` lightning 
  message.
* Add MPP support.

# 0.3.0+lightning-0.0.123 - Jul 02, 2024

## API Updates

* Use TLV for the excess_data in the ChannelAnnouncement message.
* Remove the YuvPayments feature from the ChannelContext.
* Add the rust-toolchain.toml file where the Rust v1.78.0 version is locked.
* Update the YUV dependencies versions.

## Backwards Compatibility

The nodes of this version are not compatible with the nodes of the previous
versions in case of using the YUV payments with public channels.

# 0.2.0+lightning-0.0.123 - Jun 12, 2024

* Merged the latest rust-lightning changes. See CHANGELOG.md 
  [0.0.117 - 0.0.123] for more details.

# 0.1.0+lightning-0.0.117 - May 9, 2024 - "God bless YUV"

## API Updates

* Added support of YUV payments.
* Added support for the Update balance feature, including a method
  to propose and respond to the update in the `ChannelManager` interface, such
  as `ChannelManager::update_balance`.
* `ChannelDetails` now contains YUV related fields:
    * `yuv_holder_pixel` - the current holder's YUV pixel in the channel.
    * `yuv_counterparty_pixel` - the current counterparty's YUV pixel in the
      channel.
      And the fields related to the Update balance feature:
    * `pending_update_balance` - The pending update balance proposals -
      inbound/outbound.
    * `holders_ready_to_update_msat` - holder's amount of msat in channel that
      can be used to update balance.
    * `counterpartys_ready_to_update_msat` - counterparty's amount of msat in
      channel that can be used to update balance.
* `ChannelManager::create_channel` method now allows setting the YUV pixel for
  the channel using an additional parameter - `funding_pixel`.
* The events were update to contains inforamtion that is required to comfortably
  use YUV payment. e.g. `FundingGenerationReady` event now contains the funding
  YUV pixel of the channel, `PaymentClaimable` event now contains the YUV amount
  that can be claimed, etc.
* Added methods to create YUV invoices and requests in the `lightning-invoice`
  crate.
* Modified the HTLCs routing mechanism to support YUV HTLCs.

## Backwards Compatibility

* The users must update their code to use the YUV payments or the Update balance
  feature.

## Node Compatibility
* YUV LDK nodes are compatible with non-YUV LDK nodes, but the YUV features will
  not be available for the non-YUV nodes.
