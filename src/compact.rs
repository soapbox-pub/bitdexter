//! The compact form transactions are stored in.
//!
//! Every output in the chain has a number, in the order they were created,
//! so an input names the output it spends by the difference between that
//! number and its own transaction's first output: a few bytes rather than a
//! 36-byte outpoint. Amounts are compressed as Bitcoin Core compresses them
//! in its UTXO set, which makes round amounts tiny, and standard output
//! scripts are kept as a one-byte template and the hash or key they carry.
//! Witnesses, signatures and other scripts are kept as they are. A
//! transaction's raw bytes, and so its txid, can be rebuilt exactly.
//!
//! ```text
//! tx      = flags:u8 [version:varint] [locktime:varint] n_in:varint n_out:varint input* output*
//! flags   = version code (bits 0-1: 1, 2, 3, or explicit) | segwit (bit 2)
//!         | locktime nonzero (bit 3) | coinbase (bit 4)
//! input   = [spent delta:varint] sequence:varint script_sig:bytes [witness as serialized]
//! output  = amount:varint script
//! script  = template:varint payload   (template >= 16 is a raw script of template - 16 bytes)
//! ```
//!
//! Varints here are LEB128, not Bitcoin's CompactSize.

use crate::block::{Reader as RawReader, Tx};

const FLAG_SEGWIT: u8 = 1 << 2;
const FLAG_LOCKTIME: u8 = 1 << 3;
const FLAG_COINBASE: u8 = 1 << 4;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodeError;

impl std::fmt::Display for DecodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("corrupt compact transaction")
    }
}

impl std::error::Error for DecodeError {}

pub fn write_varint(out: &mut Vec<u8>, mut n: u64) {
    while n >= 0x80 {
        out.push((n as u8) | 0x80);
        n >>= 7;
    }
    out.push(n as u8);
}

pub struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    pub fn new(data: &'a [u8]) -> Reader<'a> {
        Reader { data, pos: 0 }
    }

    pub fn varint(&mut self) -> Result<u64, DecodeError> {
        let mut n = 0u64;
        let mut shift = 0;
        loop {
            let byte = *self.data.get(self.pos).ok_or(DecodeError)?;
            self.pos += 1;
            if shift > 63 {
                return Err(DecodeError);
            }
            n |= ((byte & 0x7f) as u64) << shift;
            if byte & 0x80 == 0 {
                return Ok(n);
            }
            shift += 7;
        }
    }

    pub fn bytes(&mut self, n: usize) -> Result<&'a [u8], DecodeError> {
        let end = self.pos.checked_add(n).ok_or(DecodeError)?;
        let slice = self.data.get(self.pos..end).ok_or(DecodeError)?;
        self.pos = end;
        Ok(slice)
    }

    pub fn u8(&mut self) -> Result<u8, DecodeError> {
        Ok(self.bytes(1)?[0])
    }

    pub fn is_empty(&self) -> bool {
        self.pos == self.data.len()
    }
}

/// Bitcoin Core's `CompressAmount`.
pub fn compress_amount(mut n: u64) -> u64 {
    if n == 0 {
        return 0;
    }
    let mut e = 0;
    while n.is_multiple_of(10) && e < 9 {
        n /= 10;
        e += 1;
    }
    if e < 9 {
        let d = n % 10;
        n /= 10;
        1 + (n * 9 + d - 1) * 10 + e
    } else {
        1 + (n - 1) * 10 + 9
    }
}

/// Bitcoin Core's `DecompressAmount`.
pub fn decompress_amount(mut x: u64) -> u64 {
    if x == 0 {
        return 0;
    }
    x -= 1;
    let mut e = x % 10;
    x /= 10;
    let mut n = if e < 9 {
        let d = (x % 9) + 1;
        x /= 9;
        x.wrapping_mul(10).wrapping_add(d)
    } else {
        x.wrapping_add(1)
    };
    while e > 0 {
        n = n.wrapping_mul(10);
        e -= 1;
    }
    n
}

const RAW_SCRIPT: u64 = 16;

pub fn write_script(out: &mut Vec<u8>, script: &[u8]) {
    match script {
        [0x76, 0xa9, 0x14, hash @ .., 0x88, 0xac] if hash.len() == 20 => {
            out.push(0);
            out.extend_from_slice(hash);
        }
        [0xa9, 0x14, hash @ .., 0x87] if hash.len() == 20 => {
            out.push(1);
            out.extend_from_slice(hash);
        }
        [0x21, prefix @ (0x02 | 0x03), key @ .., 0xac] if key.len() == 32 => {
            out.push(if *prefix == 0x02 { 2 } else { 3 });
            out.extend_from_slice(key);
        }
        [0x00, 0x14, hash @ ..] if hash.len() == 20 => {
            out.push(4);
            out.extend_from_slice(hash);
        }
        [0x00, 0x20, hash @ ..] if hash.len() == 32 => {
            out.push(5);
            out.extend_from_slice(hash);
        }
        [0x51, 0x20, key @ ..] if key.len() == 32 => {
            out.push(6);
            out.extend_from_slice(key);
        }
        [0x51, 0x02, 0x4e, 0x73] => out.push(7),
        [0x41, 0x04, key @ .., 0xac] if key.len() == 64 => {
            out.push(8);
            out.extend_from_slice(key);
        }
        _ => {
            write_varint(out, RAW_SCRIPT + script.len() as u64);
            out.extend_from_slice(script);
        }
    }
}

pub fn read_script(r: &mut Reader<'_>) -> Result<Vec<u8>, DecodeError> {
    let code = r.varint()?;
    let mut script = Vec::new();
    match code {
        0 => {
            script.extend_from_slice(&[0x76, 0xa9, 0x14]);
            script.extend_from_slice(r.bytes(20)?);
            script.extend_from_slice(&[0x88, 0xac]);
        }
        1 => {
            script.extend_from_slice(&[0xa9, 0x14]);
            script.extend_from_slice(r.bytes(20)?);
            script.push(0x87);
        }
        2 | 3 => {
            script.extend_from_slice(&[0x21, code as u8]);
            script.extend_from_slice(r.bytes(32)?);
            script.push(0xac);
        }
        4 => {
            script.extend_from_slice(&[0x00, 0x14]);
            script.extend_from_slice(r.bytes(20)?);
        }
        5 => {
            script.extend_from_slice(&[0x00, 0x20]);
            script.extend_from_slice(r.bytes(32)?);
        }
        6 => {
            script.extend_from_slice(&[0x51, 0x20]);
            script.extend_from_slice(r.bytes(32)?);
        }
        7 => script.extend_from_slice(&[0x51, 0x02, 0x4e, 0x73]),
        8 => {
            script.extend_from_slice(&[0x41, 0x04]);
            script.extend_from_slice(r.bytes(64)?);
            script.push(0xac);
        }
        RAW_SCRIPT.. => {
            let len = usize::try_from(code - RAW_SCRIPT).map_err(|_| DecodeError)?;
            script.extend_from_slice(r.bytes(len)?);
        }
        _ => return Err(DecodeError),
    }
    Ok(script)
}

fn sequence_code(sequence: u32) -> u64 {
    match sequence {
        0xffff_ffff => 0,
        0xffff_fffe => 1,
        0xffff_fffd => 2,
        n => n as u64 + 3,
    }
}

fn sequence_from_code(code: u64) -> Result<u32, DecodeError> {
    Ok(match code {
        0 => 0xffff_ffff,
        1 => 0xffff_fffe,
        2 => 0xffff_fffd,
        n => u32::try_from(n - 3).map_err(|_| DecodeError)?,
    })
}

/// Appends `tx` in compact form. `first_out` is the number of its first
/// output, and `spent` the numbers of the outputs its inputs spend (empty
/// for a coinbase). Output amounts must be at most 21 million bitcoin.
pub fn encode(tx: &Tx<'_>, first_out: u64, spent: &[u64], out: &mut Vec<u8>) {
    let coinbase = tx.is_coinbase();
    let mut flags = match tx.version {
        1 => 0,
        2 => 1,
        3 => 2,
        _ => 3,
    };
    if tx.segwit {
        flags |= FLAG_SEGWIT;
    }
    if tx.locktime != 0 {
        flags |= FLAG_LOCKTIME;
    }
    if coinbase {
        flags |= FLAG_COINBASE;
    }
    out.push(flags);
    if flags & 3 == 3 {
        write_varint(out, tx.version as u32 as u64);
    }
    if tx.locktime != 0 {
        write_varint(out, tx.locktime as u64);
    }
    write_varint(out, tx.inputs.len() as u64);
    write_varint(out, tx.outputs.len() as u64);
    for (i, input) in tx.inputs.iter().enumerate() {
        if !coinbase {
            debug_assert!(spent[i] < first_out);
            write_varint(out, first_out - spent[i]);
        }
        write_varint(out, sequence_code(input.sequence));
        write_varint(out, input.script_sig.len() as u64);
        out.extend_from_slice(input.script_sig);
        if tx.segwit {
            out.extend_from_slice(input.witness);
        }
    }
    for output in &tx.outputs {
        write_varint(out, compress_amount(output.value));
        write_script(out, output.script);
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompactInput<'a> {
    /// The number of the output it spends, or `None` for a coinbase's input.
    pub spent: Option<u64>,
    pub sequence: u32,
    pub script_sig: &'a [u8],
    /// As serialized, its item count first; empty if the transaction has no
    /// witness data.
    pub witness: &'a [u8],
}

impl CompactInput<'_> {
    /// The witness's items.
    pub fn witness_items(&self) -> Vec<&[u8]> {
        if self.witness.is_empty() {
            return Vec::new();
        }
        let mut r = RawReader::new(self.witness);
        let n = r.length().unwrap_or(0);
        (0..n).map_while(|_| r.var_bytes().ok()).collect()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompactOutput {
    pub value: u64,
    pub script: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompactTx<'a> {
    pub version: i32,
    pub locktime: u32,
    pub segwit: bool,
    pub coinbase: bool,
    pub inputs: Vec<CompactInput<'a>>,
    pub outputs: Vec<CompactOutput>,
}

fn skip_witness<'a>(r: &mut Reader<'a>) -> Result<&'a [u8], DecodeError> {
    // The witness is in Bitcoin's own serialization, so it's walked as such.
    let rest = &r.data[r.pos..];
    let mut raw = RawReader::new(rest);
    let n = raw.length().map_err(|_| DecodeError)?;
    for _ in 0..n {
        raw.var_bytes().map_err(|_| DecodeError)?;
    }
    r.bytes(raw.pos())
}

pub fn decode(data: &[u8], first_out: u64) -> Result<CompactTx<'_>, DecodeError> {
    let mut r = Reader::new(data);
    let flags = r.u8()?;
    let version = match flags & 3 {
        0 => 1,
        1 => 2,
        2 => 3,
        _ => r.varint()? as u32 as i32,
    };
    let locktime = if flags & FLAG_LOCKTIME != 0 { u32::try_from(r.varint()?).map_err(|_| DecodeError)? } else { 0 };
    let segwit = flags & FLAG_SEGWIT != 0;
    let coinbase = flags & FLAG_COINBASE != 0;
    let n_in = r.varint()? as usize;
    let n_out = r.varint()? as usize;
    if n_in > data.len() || n_out > data.len() {
        return Err(DecodeError);
    }
    let mut inputs = Vec::with_capacity(n_in);
    for _ in 0..n_in {
        let spent = if coinbase {
            None
        } else {
            let delta = r.varint()?;
            Some(first_out.checked_sub(delta).ok_or(DecodeError)?)
        };
        let sequence = sequence_from_code(r.varint()?)?;
        let len = r.varint()? as usize;
        let script_sig = r.bytes(len)?;
        let witness = if segwit { skip_witness(&mut r)? } else { &[] };
        inputs.push(CompactInput { spent, sequence, script_sig, witness });
    }
    let mut outputs = Vec::with_capacity(n_out);
    for _ in 0..n_out {
        let value = decompress_amount(r.varint()?);
        let script = read_script(&mut r)?;
        outputs.push(CompactOutput { value, script });
    }
    if !r.is_empty() {
        return Err(DecodeError);
    }
    Ok(CompactTx { version, locktime, segwit, coinbase, inputs, outputs })
}

impl CompactTx<'_> {
    /// The raw transaction, given the outpoint (txid, vout) each input
    /// spends, in order. A coinbase's are ignored.
    pub fn to_raw(&self, prevouts: &[([u8; 32], u32)]) -> Vec<u8> {
        use crate::block::write_compact_size;
        let mut out = Vec::with_capacity(256);
        out.extend_from_slice(&self.version.to_le_bytes());
        if self.segwit {
            out.extend_from_slice(&[0, 1]);
        }
        write_compact_size(&mut out, self.inputs.len() as u64);
        for (i, input) in self.inputs.iter().enumerate() {
            if self.coinbase {
                out.extend_from_slice(&[0; 32]);
                out.extend_from_slice(&u32::MAX.to_le_bytes());
            } else {
                out.extend_from_slice(&prevouts[i].0);
                out.extend_from_slice(&prevouts[i].1.to_le_bytes());
            }
            write_compact_size(&mut out, input.script_sig.len() as u64);
            out.extend_from_slice(input.script_sig);
            out.extend_from_slice(&input.sequence.to_le_bytes());
        }
        write_compact_size(&mut out, self.outputs.len() as u64);
        for output in &self.outputs {
            out.extend_from_slice(&output.value.to_le_bytes());
            write_compact_size(&mut out, output.script.len() as u64);
            out.extend_from_slice(&output.script);
        }
        if self.segwit {
            for input in &self.inputs {
                out.extend_from_slice(input.witness);
            }
        }
        out.extend_from_slice(&self.locktime.to_le_bytes());
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block::parse_tx;

    #[test]
    fn amounts_round_trip() {
        for n in [0, 1, 9, 10, 546, 1000, 100_000_000, 2_099_999_997_690_000, 50 * 100_000_000, 123_456_789] {
            assert_eq!(decompress_amount(compress_amount(n)), n);
        }
        assert!(compress_amount(100_000_000) < 128);
    }

    #[test]
    fn scripts_round_trip() {
        let scripts: Vec<Vec<u8>> = vec![
            [&[0x76, 0xa9, 0x14][..], &[7; 20], &[0x88, 0xac]].concat(),
            [&[0xa9, 0x14][..], &[7; 20], &[0x87]].concat(),
            [&[0x21, 0x02][..], &[7; 32], &[0xac]].concat(),
            [&[0x21, 0x03][..], &[7; 32], &[0xac]].concat(),
            [&[0x21, 0x04][..], &[7; 32], &[0xac]].concat(),
            [&[0x00, 0x14][..], &[7; 20]].concat(),
            [&[0x00, 0x20][..], &[7; 32]].concat(),
            [&[0x51, 0x20][..], &[7; 32]].concat(),
            vec![0x51, 0x02, 0x4e, 0x73],
            [&[0x41, 0x04][..], &[7; 64], &[0xac]].concat(),
            vec![0x6a, 0x04, 1, 2, 3, 4],
            vec![],
            [&[0x00, 0x14][..], &[7; 19]].concat(),
        ];
        for script in scripts {
            let mut out = Vec::new();
            write_script(&mut out, &script);
            let mut r = Reader::new(&out);
            assert_eq!(read_script(&mut r).unwrap(), script);
            assert!(r.is_empty());
        }
    }

    #[test]
    fn tx_round_trips() {
        let hex = "01000000000102fff7f7881a8099afa6940d42d1e7f6362bec38171ea3edf433541db4e4ad969f00000000494830450221008b9d1dc26ba6a9cb62127b02742fa9d754cd3bebf337f7a55d114c8e5cdd30be022040529b194ba3f9281a99f2b1c0a19c0489bc22ede944ccf4ecbab4cc618ef3ed01eeffffffef51e1b804cc89d182d279655c3aa89e815b1b309fe287d9b2b55d57b90ec68a0100000000ffffffff02202cb206000000001976a9148280b37df378db99f66f85c95a783a76ac7a6d5988ac9093510d000000001976a9143bde42dbee7e4dbe6a21b2d50ce2f0167faa815988ac000247304402203609e17b84f6a7d30c80bfa610b5b4542f32a8a0d5447a12fb1366d7f01cc44a0220573a954c4518331561406f90300e8f3358f51928d43c212a8caed02de67eebee0121025476c2e83188368da1ff3e292e7acafcdb3566bb0ad253f62fc70f07aeeb635711000000";
        let raw = hex::decode(hex).unwrap();
        let tx = parse_tx(&raw).unwrap();
        let first_out = 1_000_000;
        let spent = [10, 999_999];
        let mut compact = Vec::new();
        encode(&tx, first_out, &spent, &mut compact);
        assert!(compact.len() < raw.len() - 50, "{} vs {}", compact.len(), raw.len());
        let decoded = decode(&compact, first_out).unwrap();
        assert_eq!(decoded.inputs[0].spent, Some(10));
        assert_eq!(decoded.inputs[1].spent, Some(999_999));
        let prevouts: Vec<_> = tx.inputs.iter().map(|i| (i.prev_txid, i.prev_vout)).collect();
        assert_eq!(decoded.to_raw(&prevouts), raw);
    }

    #[test]
    fn coinbase_round_trips() {
        let block = bitcoin::constants::genesis_block(bitcoin::Network::Bitcoin);
        let raw = bitcoin::consensus::serialize(&block.txdata[0]);
        let tx = parse_tx(&raw).unwrap();
        let mut compact = Vec::new();
        encode(&tx, 0, &[], &mut compact);
        let decoded = decode(&compact, 0).unwrap();
        assert!(decoded.coinbase);
        assert_eq!(decoded.to_raw(&[]), raw);
    }
}
