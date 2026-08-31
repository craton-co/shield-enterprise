// SPDX-License-Identifier: LicenseRef-BSL-1.1
// Copyright (c) 2026 Craton Software Company
// Licensed under the Business Source License 1.1. Converts to Apache-2.0 on 2030-09-01.
// See LICENSE at the workspace root.
#![no_main]
use libfuzzer_sys::fuzz_target;
use vs_eth_monitor::{
    AllowListEntry, DEFAULT_SIPHASH_KEYS, EthMonitor, EthMonitorConfig, EthPacket,
};

// SOME/IP UDP port — used to route packets into the SOME/IP checker so that
// the oversized-payload path gets coverage. Mirrors the private constant in
// vs-eth-monitor.
const SOMEIP_UDP_PORT: u16 = 30490;

fuzz_target!(|data: &[u8]| {
    // Need at least 6 (src_mac) + 6 (dst_mac) + 2 (ethertype) + 1 (vlan flag)
    // + 1 (dst_port flag) = 16 bytes minimum.
    if data.len() < 16 {
        return;
    }

    // --- Parse Ethernet packet fields from the fuzzer input ---

    let mut src_mac = [0u8; 6];
    src_mac.copy_from_slice(&data[0..6]);

    let mut dst_mac = [0u8; 6];
    dst_mac.copy_from_slice(&data[6..12]);

    let ethertype = u16::from_be_bytes([data[12], data[13]]);

    // Use one byte to decide VLAN presence and derive a VLAN ID.
    let vlan_flag = data[14];
    let vlan_id = if vlan_flag & 0x80 != 0 {
        // Derive a 12-bit VLAN ID from remaining bits of the flag byte.
        Some((vlan_flag as u16) & 0x0FFF)
    } else {
        None
    };

    // Use one byte to decide dst_port: bias towards SOME/IP so the
    // oversized-payload path gets meaningful coverage, but still let the
    // fuzzer explore None and arbitrary ports.
    let port_flag = data[15];
    let dst_port = match port_flag & 0b11 {
        0 => None,
        1 => Some(SOMEIP_UDP_PORT),
        2 => Some(13400), // DoIP TCP port
        _ => Some(((port_flag as u16) << 8) | (port_flag as u16)),
    };

    // Everything after the header fields is the payload.
    let payload = &data[16..];

    let pkt = EthPacket {
        src_mac,
        dst_mac,
        vlan_id,
        ethertype,
        dst_port,
        payload,
    };

    // --- Configure the monitor with some representative rules ---

    let mut config = EthMonitorConfig::default();

    // Add one allow-list entry so that the allow-list lookup path is exercised.
    config.allow_list[0] = Some(AllowListEntry {
        src_mac: [0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E],
        dst_mac: [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF],
        service_id: 0x0100,
    });
    config.allow_list_len = 1;

    // Add one allowed VLAN so the VLAN-hopping check has a comparison target.
    config.allowed_vlans[0] = Some(100);
    config.allowed_vlans_len = 1;

    // Use a somewhat low SOME/IP max length to trigger oversized-payload alerts.
    config.someip_max_length = 1024;

    let mut monitor = match EthMonitor::new(&config, DEFAULT_SIPHASH_KEYS) {
        Ok(m) => m,
        Err(_) => return,
    };

    // Derive a timestamp from the tail of the fuzz input.
    let ts: u64 = if data.len() >= 24 {
        u64::from_le_bytes([
            data[16], data[17], data[18], data[19],
            data[20], data[21], data[22], data[23],
        ])
    } else {
        0
    };

    // --- Exercise inspect_packet -- must never panic ---

    // First inspection (learns ARP bindings, starts DoIP sessions, etc.).
    let _ = monitor.inspect_packet(&pkt, ts);

    // Second inspection can trigger ARP-spoof detection against learned state.
    let _ = monitor.inspect_packet(&pkt, ts.wrapping_add(1_000));

    // Build a second packet with swapped MACs to exercise spoof-detection
    // with a different source/destination.
    let pkt2 = EthPacket {
        src_mac: dst_mac,
        dst_mac: src_mac,
        vlan_id,
        ethertype,
        dst_port,
        payload,
    };
    let _ = monitor.inspect_packet(&pkt2, ts.wrapping_add(2_000));
});
