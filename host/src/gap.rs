//! ## Generic Access Profile
//!
//! This profile defines the generic procedures related to discovery of
//! Bluetooth devices (idle mode procedures) and link management aspects
//! of connecting to Bluetooth devices (connecting mode procedures).
//! It also defines procedures related to use of different security levels.
//! In addition, this profile includes common format requirements for
//! parameters accessible on the user interface level.

use embassy_sync::blocking_mutex::raw::RawMutex;

use crate::prelude::*;
#[cfg(feature = "security")]
use crate::{Error, PacketPool};

/// Advertising packet is limited to 31 bytes. 9 of these are used by other GAP data, leaving 22 bytes for the Device Name characteristic
const DEVICE_NAME_MAX_LENGTH: usize = 22;

/// The number of attributes added by the GAP and GATT services
/// GAP_SERVICE:                      1
/// ├── DEVICE_NAME:                  2
/// ├── APPEARANCE:                   2
/// └── CENTRAL_ADDRESS_RESOLUTION:   2 (security+central only)
/// GATT_SERVICE:                   + 1
///                                 ---
///                                 = 6 (or 8 with security+central)
#[cfg(not(feature = "security"))]
pub const GAP_SERVICE_ATTRIBUTE_COUNT: usize = 6;
/// The number of attributes added by the GAP and GATT services (with security, peripheral only)
#[cfg(all(feature = "security", not(feature = "central")))]
pub const GAP_SERVICE_ATTRIBUTE_COUNT: usize = 6;
/// The number of attributes added by the GAP and GATT services (with security)
#[cfg(all(feature = "security", feature = "central"))]
pub const GAP_SERVICE_ATTRIBUTE_COUNT: usize = 8;

/// Configuration for the GAP Service.
pub enum GapConfig<'a> {
    /// Peripheral device configuration.
    Peripheral(PeripheralConfig<'a>),
    /// Central device configuration.
    Central(CentralConfig<'a>),
}

/// Configuration for a peripheral device GAP Service.
pub struct PeripheralConfig<'a> {
    /// The name of the peripheral device.
    pub name: &'a str,
    /// The representation of the external appearance of the device.
    ///
    /// Example: `&appearance::sensor::GENERIC_SENSOR.`
    pub appearance: &'a BluetoothUuid16,
    // TODO: Add more GAP parameters
    // pub preferred_connection_parameters: Option<ConnectionParameters>,
}

/// Configuration for a central device GAP Service.
pub struct CentralConfig<'a> {
    /// The name of the central device.
    pub name: &'a str,
    /// The representation of the external appearance of the device.
    ///
    /// Example: `&appearance::sensor::GENERIC_SENSOR`
    pub appearance: &'a BluetoothUuid16,
    // TODO: Add more GAP parameters
}

/// The attributes [`GapConfig::build_with_caching`] adds to the GATT service, on top of
/// [`GAP_SERVICE_ATTRIBUTE_COUNT`]: Service Changed (declaration, value and its CCCD), Client
/// Supported Features and Database Hash (declaration and value each).
#[cfg(feature = "security")]
pub const GATT_CACHING_ATTRIBUTE_COUNT: usize = 7;

/// The GATT service's characteristics for GATT caching (Core Spec Vol 3, Part G, 2.5.2 and
/// 7): what lets a bonded client keep its discovery of the database and rediscover only when
/// the database changed.
///
/// - **Service Changed** (indicate): the server indicates the affected handle range to a
///   client whose cached database is out of date ([`GattCaching::WHOLE_DATABASE`]). Its CCCD
///   is per client, and for a bonded client it must survive disconnection and power loss: keep
///   the client's attribute table ([`AttributeServer::get_client_att_table`]) with the bond and
///   restore it when the client reconnects ([`AttributeServer::set_client_att_table`]).
/// - **Client Supported Features** (read, write; per client): bit 0 set means the client uses
///   robust caching. A client may set bits but never clear them; the application rejects a
///   write that would ([`GattCaching::client_features_write_allowed`]).
/// - **Database Hash** (read): the hash of the database's structure
///   ([`AttributeTable::hash`]); [`GattCaching::set_database_hash`] stores it once every
///   service is in the table.
///
/// The application keeps the hash it last served across reboots: when it differs, every
/// bonded client is change-unaware until it is told (Service Changed, confirmed) or reads the
/// hash, and a change-unaware client with robust caching gets ATT error Database Out Of Sync
/// for its requests in the meantime.
#[cfg(feature = "security")]
#[derive(Clone, Copy, Debug)]
pub struct GattCaching {
    /// Service Changed.
    pub service_changed: Characteristic<[u8; 4]>,
    /// Client Supported Features (per client).
    pub client_supported_features: Characteristic<u8>,
    /// Database Hash.
    pub database_hash: Characteristic<[u8; 16]>,
}

#[cfg(feature = "security")]
impl GattCaching {
    /// The Service Changed value for "anything may have changed": handles 0x0001 to 0xFFFF.
    pub const WHOLE_DATABASE: [u8; 4] = [0x01, 0x00, 0xff, 0xff];

    /// Client Supported Features bit 0: the client uses robust caching.
    pub const ROBUST_CACHING: u8 = 0x01;

    /// Computes the hash of `server`'s table and stores it as the Database Hash value, as it
    /// goes over the air (least significant octet first). Call once every service is in the
    /// table; the value of the hash characteristic is not part of the hash, so this does not
    /// change it.
    pub fn set_database_hash<M: RawMutex, P: PacketPool, const AT: usize, const CN: usize>(
        &self,
        server: &AttributeServer<'_, M, P, AT, CN>,
    ) -> Result<[u8; 16], Error> {
        let hash = server.table().hash().to_le_bytes();
        self.database_hash.set(server, &hash)?;
        Ok(hash)
    }

    /// Whether a client whose Client Supported Features are `current` may write `new`: bits
    /// may be set, never cleared (Core Spec Vol 3, Part G, 7.2). A refused write gets ATT error
    /// Value Not Allowed.
    pub const fn client_features_write_allowed(current: u8, new: u8) -> bool {
        current & !new == 0
    }
}

impl<'a> GapConfig<'a> {
    /// Create a default peripheral configuration.
    ///
    /// This configuration will use the `UNKNOWN` appearance.
    pub fn default(name: &'a str) -> Self {
        GapConfig::Peripheral(PeripheralConfig {
            name,
            appearance: &appearance::UNKNOWN,
        })
    }

    /// Add the GAP config to the attribute table
    pub fn build<M: RawMutex, const MAX: usize>(
        self,
        table: &mut AttributeTable<'a, M, MAX>,
    ) -> Result<(), &'static str> {
        self.build_gap(table)?;
        table.add_service(Service::new(service::GATT));
        Ok(())
    }

    /// Add the GAP config to the attribute table, with a GATT service that supports GATT
    /// caching: Service Changed, Client Supported Features and Database Hash ([`GattCaching`]).
    /// The table needs [`GATT_CACHING_ATTRIBUTE_COUNT`] attributes more than [`build`] does
    /// (`attribute_table_size` of `#[gatt_server]`); build the server from the table with
    /// `new(table)` and then call [`GattCaching::set_database_hash`].
    ///
    /// [`build`]: Self::build
    #[cfg(feature = "security")]
    pub fn build_with_caching<M: RawMutex, const MAX: usize>(
        self,
        table: &mut AttributeTable<'a, M, MAX>,
    ) -> Result<GattCaching, &'static str> {
        self.build_gap(table)?;
        if table.len() + 1 + GATT_CACHING_ATTRIBUTE_COUNT > MAX {
            return Err("Attribute table too small for the GATT caching characteristics");
        }
        let mut gatt = table.add_service(Service::new(service::GATT));
        // the order of the specification's example database (Vol 3, Part G, Appendix B)
        let service_changed = gatt
            .add_characteristic_small(
                characteristic::SERVICE_CHANGED,
                [CharacteristicProp::Indicate],
                [0u8; 4],
            )
            .build();
        let client_supported_features = gatt
            .add_characteristic_client::<u8, _, _>(
                characteristic::CLIENT_SUPPORTED_FEATURES,
                [CharacteristicProp::Read, CharacteristicProp::Write],
            )
            .build();
        let database_hash = gatt
            .add_characteristic_small(characteristic::DATABASE_HASH, [CharacteristicProp::Read], [0u8; 16])
            .build();
        gatt.build();
        Ok(GattCaching {
            service_changed,
            client_supported_features,
            database_hash,
        })
    }

    fn build_gap<M: RawMutex, const MAX: usize>(
        &self,
        table: &mut AttributeTable<'a, M, MAX>,
    ) -> Result<(), &'static str> {
        let (name, appearance) = match self {
            GapConfig::Peripheral(config) => (config.name, config.appearance),
            GapConfig::Central(config) => (config.name, config.appearance),
        };
        // Store the name by reference (lives for `'a`); a one-shot StaticCell
        // would panic if the server is ever built twice.
        if name.len() > DEVICE_NAME_MAX_LENGTH {
            return Err("Device name is too long. Max length is 22 bytes");
        }

        let mut gap_builder = table.add_service(Service::new(service::GAP));
        gap_builder.add_characteristic_ro(characteristic::DEVICE_NAME, name);
        gap_builder.add_characteristic_ro(characteristic::APPEARANCE, appearance);
        #[cfg(all(feature = "security", feature = "central"))]
        gap_builder.add_characteristic_ro(characteristic::CENTRAL_ADDRESS_RESOLUTION, &1u8);
        gap_builder.build();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use embassy_sync::blocking_mutex::raw::NoopRawMutex;

    use super::*;

    /// The GATT service with caching is the specification's example database (the same
    /// handles, properties and order), so its hash is the example's; and the hash goes into
    /// the Database Hash characteristic as it goes over the air.
    #[cfg(all(feature = "security", not(feature = "central")))]
    #[test]
    fn gatt_caching_service() {
        use crate::attribute_server::AttributeServer;
        use crate::prelude::DefaultPacketPool;

        const SIZE: usize = GAP_SERVICE_ATTRIBUTE_COUNT + GATT_CACHING_ATTRIBUTE_COUNT;
        let mut table: AttributeTable<'_, NoopRawMutex, SIZE> = AttributeTable::new();
        let caching = GapConfig::Peripheral(PeripheralConfig {
            name: "",
            appearance: &appearance::UNKNOWN,
        })
        .build_with_caching(&mut table)
        .unwrap();
        assert_eq!(table.len(), SIZE);
        assert_eq!(caching.service_changed.handle, 0x0008);
        assert_eq!(caching.service_changed.cccd_handle, Some(0x0009));
        assert_eq!(caching.client_supported_features.handle, 0x000b);
        assert_eq!(caching.database_hash.handle, 0x000d);
        // Core Spec Vol 3, Part G, Appendix B: GAP and GATT services
        assert_eq!(table.hash(), 0x16ce756326c5062bf74022f845c2b21f);

        let server = AttributeServer::<_, DefaultPacketPool, SIZE, 1>::new(table);
        let hash = caching.set_database_hash(&server).unwrap();
        assert_eq!(hash, 0x16ce756326c5062bf74022f845c2b21fu128.to_le_bytes());
    }

    /// With any GAP service: the hash is stored as it goes over the air, storing it does not
    /// change it, and a table too small is refused rather than overrun.
    #[cfg(feature = "security")]
    #[test]
    fn gatt_caching_stores_the_hash() {
        use crate::attribute_server::AttributeServer;
        use crate::prelude::DefaultPacketPool;

        const SIZE: usize = GAP_SERVICE_ATTRIBUTE_COUNT + GATT_CACHING_ATTRIBUTE_COUNT;
        let mut table: AttributeTable<'_, NoopRawMutex, SIZE> = AttributeTable::new();
        let caching = GapConfig::default("nacra").build_with_caching(&mut table).unwrap();
        assert_eq!(table.len(), SIZE);
        let expected = table.hash();
        let server = AttributeServer::<_, DefaultPacketPool, SIZE, 1>::new(table);
        let hash = caching.set_database_hash(&server).unwrap();
        assert_eq!(hash, expected.to_le_bytes());
        assert_eq!(caching.database_hash.get(&server).unwrap(), hash);
        assert_eq!(server.table().hash(), expected);
        assert_eq!(
            caching.service_changed.cccd_handle,
            Some(caching.service_changed.handle + 1)
        );

        let mut small: AttributeTable<'_, NoopRawMutex, { SIZE - 1 }> = AttributeTable::new();
        assert!(GapConfig::default("").build_with_caching(&mut small).is_err());
    }

    #[cfg(feature = "security")]
    #[test]
    fn client_features_bits_are_never_cleared() {
        let allowed = GattCaching::client_features_write_allowed;
        assert!(allowed(0, 0));
        assert!(allowed(0, GattCaching::ROBUST_CACHING));
        assert!(allowed(0b001, 0b011));
        assert!(!allowed(GattCaching::ROBUST_CACHING, 0));
        assert!(!allowed(0b011, 0b010));
    }

    // Building the GAP config twice must not panic. With the one-shot StaticCell
    // the second build panicked ("StaticCell already full").
    #[test]
    fn gap_config_can_be_built_twice() {
        for _ in 0..2 {
            let mut table: AttributeTable<'_, NoopRawMutex, 16> = AttributeTable::new();
            GapConfig::Peripheral(PeripheralConfig {
                name: "trouble",
                appearance: &appearance::UNKNOWN,
            })
            .build(&mut table)
            .unwrap();
        }
    }
}
