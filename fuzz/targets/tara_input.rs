// SPDX-License-Identifier: LicenseRef-BSL-1.1
// Copyright (c) 2026 Craton Software Company
// Licensed under the Business Source License 1.1. Converts to Apache-2.0 on 2030-09-01.
// See LICENSE at the workspace root.
#![no_main]
use libfuzzer_sys::arbitrary;
use libfuzzer_sys::arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use vs_report_iso21434::generate_tara_from_catalog;
use vs_report_iso21434::risk::{DamageScenario, ImpactLevel};

#[derive(Arbitrary, Debug)]
struct Input {
    asset_ids: [u16; 4],
    damage_selectors: [u8; 4],
    mitigations: [bool; 4],
    damage_count: u8,
    threat_ids: [u16; 4],
}

fn impact_from(b: u8) -> ImpactLevel {
    match b % 4 {
        0 => ImpactLevel::Negligible,
        1 => ImpactLevel::Moderate,
        2 => ImpactLevel::Major,
        _ => ImpactLevel::Severe,
    }
}

fuzz_target!(|inp: Input| {
    let damages = [
        DamageScenario {
            threat_id: inp.threat_ids[0],
            safety_impact: impact_from(inp.damage_selectors[0]),
            financial_impact: impact_from(inp.damage_selectors[0] >> 2),
            operational_impact: impact_from(inp.damage_selectors[0] >> 4),
            privacy_impact: impact_from(inp.damage_selectors[0] >> 6),
        },
        DamageScenario {
            threat_id: inp.threat_ids[1],
            safety_impact: impact_from(inp.damage_selectors[1]),
            financial_impact: impact_from(inp.damage_selectors[1] >> 2),
            operational_impact: impact_from(inp.damage_selectors[1] >> 4),
            privacy_impact: impact_from(inp.damage_selectors[1] >> 6),
        },
        DamageScenario {
            threat_id: inp.threat_ids[2],
            safety_impact: impact_from(inp.damage_selectors[2]),
            financial_impact: impact_from(inp.damage_selectors[2] >> 2),
            operational_impact: impact_from(inp.damage_selectors[2] >> 4),
            privacy_impact: impact_from(inp.damage_selectors[2] >> 6),
        },
        DamageScenario {
            threat_id: inp.threat_ids[3],
            safety_impact: impact_from(inp.damage_selectors[3]),
            financial_impact: impact_from(inp.damage_selectors[3] >> 2),
            operational_impact: impact_from(inp.damage_selectors[3] >> 4),
            privacy_impact: impact_from(inp.damage_selectors[3] >> 6),
        },
    ];

    let _ = generate_tara_from_catalog(
        &inp.asset_ids,
        &damages,
        &inp.mitigations,
        inp.damage_count as usize,
    );
});
