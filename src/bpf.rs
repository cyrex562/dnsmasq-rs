#![cfg(feature = "bpf")]

//! BPF packet-filter builder for DHCP.
//!
//! Builds `sock_filter` instruction sequences that can be attached to a raw
//! socket to accept only DHCP traffic, mirroring the filter in the original
//! `bpf.c`.

// ─── Types ───────────────────────────────────────────────────────────────────

/// A single BPF instruction (`struct sock_filter`).
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct BpfInstruction {
    pub code: u16,
    pub jt:   u8,
    pub jf:   u8,
    pub k:    u32,
}

impl BpfInstruction {
    const fn new(code: u16, jt: u8, jf: u8, k: u32) -> Self {
        Self { code, jt, jf, k }
    }
}

// ─── Opcodes ─────────────────────────────────────────────────────────────────

/// BPF opcode constants (Linux `<linux/filter.h>`).
pub mod bpf_opcodes {
    pub const BPF_LD:   u16 = 0x00;
    pub const BPF_JMP:  u16 = 0x05;
    pub const BPF_RET:  u16 = 0x06;
    pub const BPF_H:    u16 = 0x08; // half-word operand size
    pub const BPF_B:    u16 = 0x10; // byte operand size
    pub const BPF_ABS:  u16 = 0x20; // absolute offset addressing
    pub const BPF_JEQ:  u16 = 0x10; // jump-if-equal
    pub const BPF_K:    u16 = 0x00; // use constant k
    pub const BPF_PASS: u32 = 0xffff_ffff; // accept packet
    pub const BPF_DROP: u32 = 0;           // drop packet
}

use bpf_opcodes::*;

// Ethernet header offset to EtherType (14 bytes) + IPv4 header (20 bytes).
// Offsets are relative to the start of the Ethernet frame.
const ETH_HDR: u32     = 14;
const IP_PROTO_OFF: u32 = ETH_HDR + 9;   // protocol field in IP header
const IP_PROTO_UDP: u32 = 17;
const UDP_DPORT_OFF: u32 = ETH_HDR + 20 + 2; // UDP destination port

// ─── Public builders ─────────────────────────────────────────────────────────

/// Build a BPF filter program that accepts UDP packets on port 67 (DHCP server).
///
/// The generated filter:
/// 1. Loads the IP protocol byte.
/// 2. Checks for UDP (17); drops anything else.
/// 3. Loads the UDP destination port.
/// 4. Accepts if port == 67, otherwise drops.
pub fn build_dhcp_filter() -> Vec<BpfInstruction> {
    build_udp_port_filter(67)
}

/// Build a BPF filter that accepts only UDP packets destined for `agent_port`.
pub fn build_relay_filter(agent_port: u16) -> Vec<BpfInstruction> {
    build_udp_port_filter(agent_port)
}

// ─── Internal ────────────────────────────────────────────────────────────────

fn build_udp_port_filter(port: u16) -> Vec<BpfInstruction> {
    // Instruction offsets for jt/jf are relative to the *next* instruction.
    //
    // [0] ld  byte [IP proto offset]
    // [1] jeq UDP(17)  ? fall-through : jump to DROP
    // [2] ld  half [UDP dst-port offset]
    // [3] jeq port     ? fall-through : jump to DROP
    // [4] ret BPF_PASS
    // [5] ret BPF_DROP
    vec![
        // Load IP protocol byte
        BpfInstruction::new(BPF_LD | BPF_B | BPF_ABS, 0, 0, IP_PROTO_OFF),
        // If protocol != UDP (17), jump to DROP (index 5, 3 instructions away)
        BpfInstruction::new(BPF_JMP | BPF_JEQ | BPF_K, 0, 3, IP_PROTO_UDP),
        // Load UDP destination port (half-word)
        BpfInstruction::new(BPF_LD | BPF_H | BPF_ABS, 0, 0, UDP_DPORT_OFF),
        // If port != target, jump to DROP (index 5, 1 instruction away)
        BpfInstruction::new(BPF_JMP | BPF_JEQ | BPF_K, 0, 1, port as u32),
        // PASS
        BpfInstruction::new(BPF_RET | BPF_K, 0, 0, BPF_PASS),
        // DROP
        BpfInstruction::new(BPF_RET | BPF_K, 0, 0, BPF_DROP),
    ]
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_dhcp_filter_non_empty() {
        let f = build_dhcp_filter();
        assert!(!f.is_empty());
    }

    #[test]
    fn test_build_relay_filter_non_empty() {
        let f = build_relay_filter(67);
        assert!(!f.is_empty());
    }

    #[test]
    fn test_bpf_instruction_fields_accessible() {
        let instr = BpfInstruction { code: 0x06, jt: 0, jf: 0, k: 0xffff_ffff };
        assert_eq!(instr.code, 0x06);
        assert_eq!(instr.k,    0xffff_ffff);
    }

    #[test]
    fn test_dhcp_filter_last_instruction_is_drop() {
        let f = build_dhcp_filter();
        let last = f.last().unwrap();
        assert_eq!(last.k, bpf_opcodes::BPF_DROP);
    }

    #[test]
    fn test_relay_filter_targets_correct_port() {
        let port: u16 = 1234;
        let f = build_relay_filter(port);
        // The port comparison is the 4th instruction (index 3).
        assert_eq!(f[3].k, port as u32);
    }
}
