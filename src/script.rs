//! Scripts as people see them: their type, address and assembly, in the
//! words Esplora uses.

use bitcoin::address::NetworkUnchecked;
use bitcoin::{Address, Network, Script};

/// The type of an output script, as Esplora names it (and mempool.space,
/// for pay-to-anchor).
pub fn script_type(bytes: &[u8]) -> &'static str {
    let script = Script::from_bytes(bytes);
    if bytes.is_empty() {
        "empty"
    } else if script.is_op_return() {
        "op_return"
    } else if script.is_p2pk() {
        "p2pk"
    } else if script.is_p2pkh() {
        "p2pkh"
    } else if script.is_p2sh() {
        "p2sh"
    } else if script.is_p2wpkh() {
        "v0_p2wpkh"
    } else if script.is_p2wsh() {
        "v0_p2wsh"
    } else if script.is_p2tr() {
        "v1_p2tr"
    } else if bytes == [0x51, 0x02, 0x4e, 0x73] {
        "anchor"
    } else if script.is_multisig() {
        "multisig"
    } else if provably_unspendable(script) {
        "provably_unspendable"
    } else {
        "unknown"
    }
}

/// As Esplora decides it, with rust-bitcoin's method.
#[allow(deprecated)]
fn provably_unspendable(script: &Script) -> bool {
    script.is_provably_unspendable()
}

pub fn address(bytes: &[u8], network: Network) -> Option<String> {
    Address::from_script(Script::from_bytes(bytes), network).ok().map(|a| a.to_string())
}

pub fn asm(bytes: &[u8]) -> String {
    Script::from_bytes(bytes).to_asm_string()
}

/// The output script an address pays, if it's an address of `network`.
pub fn parse_address(s: &str, network: Network) -> Option<Vec<u8>> {
    let address: Address<NetworkUnchecked> = s.parse().ok()?;
    Some(address.require_network(network).ok()?.script_pubkey().into_bytes())
}

/// The last data a script pushes, as a P2SH spend's redeem script is.
pub fn last_push(bytes: &[u8]) -> Option<Vec<u8>> {
    use bitcoin::script::Instruction;
    let mut last = None;
    for instruction in Script::from_bytes(bytes).instructions() {
        match instruction.ok()? {
            Instruction::PushBytes(data) => last = Some(data.as_bytes().to_vec()),
            Instruction::Op(_) => last = None,
        }
    }
    last
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn types_and_addresses() {
        let p2wpkh = hex::decode("0014751e76e8199196d454941c45d1b3a323f1433bd6").unwrap();
        assert_eq!(script_type(&p2wpkh), "v0_p2wpkh");
        assert_eq!(address(&p2wpkh, Network::Bitcoin).unwrap(), "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4");
        assert_eq!(parse_address("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4", Network::Bitcoin).unwrap(), p2wpkh);
        assert!(parse_address("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4", Network::Testnet4).is_none());
        assert_eq!(asm(&p2wpkh), "OP_0 OP_PUSHBYTES_20 751e76e8199196d454941c45d1b3a323f1433bd6");
        assert_eq!(script_type(&[0x6a, 0x01, 0x00]), "op_return");
        assert_eq!(script_type(&[0x51, 0x02, 0x4e, 0x73]), "anchor");
        assert_eq!(script_type(&[]), "empty");
    }
}
