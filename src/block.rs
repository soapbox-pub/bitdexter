//! Blocks and transactions parsed in place, as slices of the bytes they came
//! in, with their hashes computed once.

use crate::hash::{Hash, sha256d, sha256d_parts};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseError(pub &'static str);

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.0)
    }
}

impl std::error::Error for ParseError {}

pub type Result<T> = std::result::Result<T, ParseError>;

/// A cursor over bytes in Bitcoin's serialization.
pub struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    pub fn new(data: &'a [u8]) -> Reader<'a> {
        Reader { data, pos: 0 }
    }

    pub fn pos(&self) -> usize {
        self.pos
    }

    pub fn is_empty(&self) -> bool {
        self.pos == self.data.len()
    }

    pub fn remaining(&self) -> usize {
        self.data.len() - self.pos
    }

    pub fn bytes(&mut self, n: usize) -> Result<&'a [u8]> {
        if self.remaining() < n {
            return Err(ParseError("unexpected end of data"));
        }
        let slice = &self.data[self.pos..self.pos + n];
        self.pos += n;
        Ok(slice)
    }

    pub fn array<const N: usize>(&mut self) -> Result<[u8; N]> {
        Ok(self.bytes(N)?.try_into().unwrap())
    }

    pub fn u8(&mut self) -> Result<u8> {
        Ok(self.bytes(1)?[0])
    }

    pub fn peek(&self, at: usize) -> Option<u8> {
        self.data.get(self.pos + at).copied()
    }

    pub fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_le_bytes(self.array()?))
    }

    pub fn u64(&mut self) -> Result<u64> {
        Ok(u64::from_le_bytes(self.array()?))
    }

    /// A CompactSize, refusing any that isn't in its shortest form, as Bitcoin
    /// Core does.
    pub fn compact_size(&mut self) -> Result<u64> {
        let first = self.u8()?;
        let value = match first {
            0..=0xfc => return Ok(first as u64),
            0xfd => u16::from_le_bytes(self.array()?) as u64,
            0xfe => self.u32()? as u64,
            0xff => self.u64()?,
        };
        let min = match first {
            0xfd => 0xfd,
            0xfe => 0x1_0000,
            _ => 0x1_0000_0000,
        };
        if value < min {
            return Err(ParseError("non-canonical CompactSize"));
        }
        Ok(value)
    }

    /// A CompactSize used as a length or count, which can't be more than
    /// what's left to read.
    pub fn length(&mut self) -> Result<usize> {
        let n = self.compact_size()?;
        if n > self.remaining() as u64 {
            return Err(ParseError("length past end of data"));
        }
        Ok(n as usize)
    }

    /// A CompactSize-prefixed byte string.
    pub fn var_bytes(&mut self) -> Result<&'a [u8]> {
        let n = self.length()?;
        self.bytes(n)
    }
}

pub fn write_compact_size(out: &mut Vec<u8>, n: u64) {
    match n {
        0..=0xfc => out.push(n as u8),
        0xfd..=0xffff => {
            out.push(0xfd);
            out.extend_from_slice(&(n as u16).to_le_bytes());
        }
        0x1_0000..=0xffff_ffff => {
            out.push(0xfe);
            out.extend_from_slice(&(n as u32).to_le_bytes());
        }
        _ => {
            out.push(0xff);
            out.extend_from_slice(&n.to_le_bytes());
        }
    }
}

pub fn compact_size_len(n: u64) -> usize {
    match n {
        0..=0xfc => 1,
        0xfd..=0xffff => 3,
        0x1_0000..=0xffff_ffff => 5,
        _ => 9,
    }
}

#[derive(Debug, Clone)]
pub struct Input<'a> {
    pub prev_txid: Hash,
    pub prev_vout: u32,
    pub script_sig: &'a [u8],
    pub sequence: u32,
    /// The input's witness as serialized, its item count first; empty when
    /// the transaction has no witness data at all.
    pub witness: &'a [u8],
}

impl Input<'_> {
    pub fn is_null_prevout(&self) -> bool {
        self.prev_vout == u32::MAX && self.prev_txid == [0; 32]
    }
}

#[derive(Debug, Clone)]
pub struct Output<'a> {
    pub value: u64,
    pub script: &'a [u8],
}

#[derive(Debug, Clone)]
pub struct Tx<'a> {
    pub raw: &'a [u8],
    pub version: i32,
    pub segwit: bool,
    pub inputs: Vec<Input<'a>>,
    pub outputs: Vec<Output<'a>>,
    pub locktime: u32,
    /// Its size without witness data.
    pub base_size: usize,
    pub txid: Hash,
    pub wtxid: Hash,
}

impl Tx<'_> {
    pub fn size(&self) -> usize {
        self.raw.len()
    }

    pub fn weight(&self) -> usize {
        self.base_size * 3 + self.raw.len()
    }

    pub fn is_coinbase(&self) -> bool {
        self.inputs.len() == 1 && self.inputs[0].is_null_prevout()
    }
}

/// Skips one serialized witness stack, returning it whole.
fn read_witness<'a>(r: &mut Reader<'a>, data: &'a [u8]) -> Result<&'a [u8]> {
    let start = r.pos();
    let items = r.length()?;
    for _ in 0..items {
        r.var_bytes()?;
    }
    Ok(&data[start..r.pos()])
}

/// Parses one transaction from the front of `r`.
pub fn read_tx<'a>(r: &mut Reader<'a>, data: &'a [u8]) -> Result<Tx<'a>> {
    let start = r.pos();
    let version = r.u32()? as i32;
    let mut segwit = false;
    if r.peek(0) == Some(0) {
        // An empty input list can only be the segwit marker.
        r.u8()?;
        let flags = r.u8()?;
        if flags != 1 {
            return Err(ParseError("unknown transaction optional data"));
        }
        segwit = true;
    }
    let io_start = r.pos();
    // Room for as many as there are bytes left for, at their smallest.
    let n_in = r.length()?;
    let mut inputs = Vec::with_capacity(n_in.min(r.remaining() / 41));
    for _ in 0..n_in {
        let prev_txid = r.array::<32>()?;
        let prev_vout = r.u32()?;
        let script_sig = r.var_bytes()?;
        let sequence = r.u32()?;
        inputs.push(Input { prev_txid, prev_vout, script_sig, sequence, witness: &[] });
    }
    let n_out = r.length()?;
    let mut outputs = Vec::with_capacity(n_out.min(r.remaining() / 9));
    for _ in 0..n_out {
        let value = r.u64()?;
        let script = r.var_bytes()?;
        outputs.push(Output { value, script });
    }
    let io_end = r.pos();
    if segwit {
        let mut any = false;
        for input in inputs.iter_mut() {
            input.witness = read_witness(r, data)?;
            any |= input.witness != [0];
        }
        if !any {
            return Err(ParseError("superfluous witness record"));
        }
    }
    let locktime_bytes = r.bytes(4)?;
    let locktime = u32::from_le_bytes(locktime_bytes.try_into().unwrap());
    let raw = &data[start..r.pos()];
    let version_bytes = &raw[..4];
    let (txid, wtxid, base_size) = if segwit {
        let txid = sha256d_parts(&[version_bytes, &data[io_start..io_end], locktime_bytes]);
        (txid, sha256d(raw), 4 + (io_end - io_start) + 4)
    } else {
        let txid = sha256d(raw);
        (txid, txid, raw.len())
    };
    Ok(Tx { raw, version, segwit, inputs, outputs, locktime, base_size, txid, wtxid })
}

pub fn parse_tx(data: &[u8]) -> Result<Tx<'_>> {
    let mut r = Reader::new(data);
    let tx = read_tx(&mut r, data)?;
    if !r.is_empty() {
        return Err(ParseError("trailing data after transaction"));
    }
    Ok(tx)
}

#[derive(Debug)]
pub struct Block<'a> {
    pub raw: &'a [u8],
    pub header: &'a [u8; 80],
    pub txs: Vec<Tx<'a>>,
}

impl Block<'_> {
    pub fn hash(&self) -> Hash {
        sha256d(self.header)
    }

    pub fn prev_hash(&self) -> Hash {
        self.header[4..36].try_into().unwrap()
    }

    pub fn merkle_root(&self) -> Hash {
        self.header[36..68].try_into().unwrap()
    }

    pub fn time(&self) -> u32 {
        u32::from_le_bytes(self.header[68..72].try_into().unwrap())
    }

    pub fn size(&self) -> usize {
        self.raw.len()
    }

    /// Its size without witness data.
    pub fn base_size(&self) -> usize {
        let txs: usize = self.txs.iter().map(|tx| tx.base_size).sum();
        80 + compact_size_len(self.txs.len() as u64) + txs
    }

    pub fn weight(&self) -> usize {
        self.base_size() * 3 + self.raw.len()
    }
}

pub fn parse_block(data: &[u8]) -> Result<Block<'_>> {
    let mut r = Reader::new(data);
    let header: &[u8; 80] = r.bytes(80)?.try_into().unwrap();
    let n = r.length()?;
    let mut txs = Vec::with_capacity(n.min(r.remaining() / 60));
    for _ in 0..n {
        txs.push(read_tx(&mut r, data)?);
    }
    if !r.is_empty() {
        return Err(ParseError("trailing data after block"));
    }
    Ok(Block { raw: data, header, txs })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::{merkle_root, to_hex_rev};
    use bitcoin::consensus::serialize;

    #[test]
    fn parses_genesis_like_rust_bitcoin() {
        for network in [bitcoin::Network::Bitcoin, bitcoin::Network::Testnet4, bitcoin::Network::Signet] {
            let block = bitcoin::constants::genesis_block(network);
            let raw = serialize(&block);
            let parsed = parse_block(&raw).unwrap();
            assert_eq!(to_hex_rev(&parsed.hash()), block.block_hash().to_string());
            assert_eq!(parsed.txs.len(), 1);
            assert_eq!(to_hex_rev(&parsed.txs[0].txid), block.txdata[0].compute_txid().to_string());
            assert!(parsed.txs[0].is_coinbase());
            assert_eq!(merkle_root(vec![parsed.txs[0].txid]).0, parsed.merkle_root());
            assert_eq!(parsed.weight(), block.weight().to_wu() as usize);
        }
    }

    #[test]
    fn parses_segwit_tx() {
        // A P2WPKH spend from BIP143's examples, signed.
        let hex = "01000000000102fff7f7881a8099afa6940d42d1e7f6362bec38171ea3edf433541db4e4ad969f00000000494830450221008b9d1dc26ba6a9cb62127b02742fa9d754cd3bebf337f7a55d114c8e5cdd30be022040529b194ba3f9281a99f2b1c0a19c0489bc22ede944ccf4ecbab4cc618ef3ed01eeffffffef51e1b804cc89d182d279655c3aa89e815b1b309fe287d9b2b55d57b90ec68a0100000000ffffffff02202cb206000000001976a9148280b37df378db99f66f85c95a783a76ac7a6d5988ac9093510d000000001976a9143bde42dbee7e4dbe6a21b2d50ce2f0167faa815988ac000247304402203609e17b84f6a7d30c80bfa610b5b4542f32a8a0d5447a12fb1366d7f01cc44a0220573a954c4518331561406f90300e8f3358f51928d43c212a8caed02de67eebee0121025476c2e83188368da1ff3e292e7acafcdb3566bb0ad253f62fc70f07aeee635711000000";
        let raw = hex::decode(hex).unwrap();
        let tx = parse_tx(&raw).unwrap();
        let theirs: bitcoin::Transaction = bitcoin::consensus::deserialize(&raw).unwrap();
        assert!(tx.segwit);
        assert_eq!(to_hex_rev(&tx.txid), theirs.compute_txid().to_string());
        assert_eq!(to_hex_rev(&tx.wtxid), theirs.compute_wtxid().to_string());
        assert_eq!(tx.weight(), theirs.weight().to_wu() as usize);
        assert_eq!(tx.inputs[0].witness, &[0]);
        assert_eq!(tx.inputs[1].witness[0], 2);
        assert_eq!(tx.locktime, 17);
    }

    #[test]
    fn refuses_noncanonical_sizes() {
        let mut r = Reader::new(&[0xfd, 0x10, 0x00]);
        assert!(r.compact_size().is_err());
        let mut r = Reader::new(&[0xfd, 0xfd, 0x00]);
        assert_eq!(r.compact_size().unwrap(), 0xfd);
    }
}
