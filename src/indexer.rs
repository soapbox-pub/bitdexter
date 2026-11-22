//! The thread that indexes blocks, in order, as the node hands them over.
//!
//! It commits whenever it has nothing waiting, so a block at the tip is
//! visible as soon as it's indexed, and during initial sync every ten
//! seconds or so (see [`Writer::should_commit`]).

use std::time::{Duration, Instant};

use bitcoin::BlockHash;
use bitcoin::hashes::Hash as _;
use tokio::sync::mpsc;

use crate::block::parse_block;
use crate::store::{ConnectError, Writer};
use crate::validate::check_block;

pub enum Command {
    Connect { height: u32, hash: BlockHash, bytes: Vec<u8> },
    /// Disconnect blocks until `height` is the tip.
    Rewind { height: u32 },
}

pub enum Event {
    Connected { height: u32 },
    /// The block isn't valid. If `mutated`, it's the copy that isn't, not
    /// the block its header names: another may be.
    Rejected { height: u32, hash: BlockHash, reason: String, mutated: bool },
    Rewound { height: u32 },
    Failed(String),
}

/// Reasons a block can be invalid that mean only that its transactions
/// aren't the ones its header commits to.
fn is_mutation(reason: &str) -> bool {
    matches!(
        reason,
        "bad-txnmrklroot" | "bad-txns-duplicate" | "bad-witness-merkle-match" | "bad-witness-nonce-size" | "unexpected-witness"
    )
}

struct Progress {
    since: Instant,
    blocks: u64,
    txs: u64,
    bytes: u64,
}

pub fn spawn(
    mut writer: Writer,
    mut commands: mpsc::UnboundedReceiver<Command>,
    events: mpsc::UnboundedSender<Event>,
) -> std::thread::JoinHandle<()> {
    std::thread::Builder::new()
        .name("indexer".into())
        .spawn(move || {
            let mut progress = Progress { since: Instant::now(), blocks: 0, txs: 0, bytes: 0 };
            loop {
                let command = match commands.try_recv() {
                    Ok(command) => command,
                    Err(mpsc::error::TryRecvError::Empty) => {
                        if let Err(err) = writer.commit() {
                            let _ = events.send(Event::Failed(format!("committing: {err:#}")));
                            return;
                        }
                        match commands.blocking_recv() {
                            Some(command) => command,
                            None => break,
                        }
                    }
                    Err(mpsc::error::TryRecvError::Disconnected) => break,
                };
                match command {
                    Command::Connect { height, hash, bytes } => {
                        if height != writer.next_height() {
                            // Sent before a block it builds on was rejected.
                            continue;
                        }
                        match connect(&mut writer, height, hash, &bytes, &mut progress) {
                            Ok(()) => {
                                let _ = events.send(Event::Connected { height });
                            }
                            Err(ConnectError::Invalid(invalid)) => {
                                let mutated = is_mutation(&invalid.0) || invalid.0.starts_with("parse:");
                                tracing::warn!("block {height} {hash} is invalid: {invalid}");
                                let _ = events.send(Event::Rejected { height, hash, reason: invalid.0, mutated });
                            }
                            Err(ConnectError::Io(err)) => {
                                let _ = events.send(Event::Failed(format!("indexing block {height}: {err:#}")));
                                return;
                            }
                        }
                        if writer.should_commit()
                            && let Err(err) = writer.commit()
                        {
                            let _ = events.send(Event::Failed(format!("committing: {err:#}")));
                            return;
                        }
                    }
                    Command::Rewind { height } => {
                        while writer.next_height() > height + 1 {
                            let tip = writer.next_height() - 1;
                            tracing::info!("disconnecting block {tip}");
                            if let Err(err) = writer.disconnect_tip() {
                                let _ = events.send(Event::Failed(format!("disconnecting block {tip}: {err:#}")));
                                return;
                            }
                        }
                        let _ = events.send(Event::Rewound { height });
                    }
                }
                if progress.since.elapsed() >= Duration::from_secs(10) {
                    log_progress(&writer, &mut progress);
                }
            }
            if let Err(err) = writer.commit() {
                tracing::error!("committing on the way out: {err:#}");
            }
        })
        .expect("spawning the indexer")
}

fn connect(
    writer: &mut Writer,
    height: u32,
    hash: BlockHash,
    bytes: &[u8],
    progress: &mut Progress,
) -> Result<(), ConnectError> {
    let invalid = |reason: String| ConnectError::Invalid(crate::validate::Invalid(reason));
    let block = parse_block(bytes).map_err(|err| invalid(format!("parse: {err}")))?;
    if block.hash() != hash.to_byte_array() {
        return Err(invalid("parse: a different block".into()));
    }
    check_block(&block, height, writer.store.chain).map_err(ConnectError::Invalid)?;
    writer.connect(&block)?;
    progress.blocks += 1;
    progress.txs += block.txs.len() as u64;
    progress.bytes += bytes.len() as u64;
    Ok(())
}

fn log_progress(writer: &Writer, progress: &mut Progress) {
    let secs = progress.since.elapsed().as_secs_f64();
    if progress.blocks > 0 {
        let tip = writer.next_height() - 1;
        let time = writer.block(tip).time();
        let date = chrono_date(time);
        tracing::info!(
            "indexed to block {tip} ({date}): {:.0} blocks/s, {:.0} tx/s, {:.1} MB/s",
            progress.blocks as f64 / secs,
            progress.txs as f64 / secs,
            progress.bytes as f64 / secs / 1e6,
        );
    }
    *progress = Progress { since: Instant::now(), blocks: 0, txs: 0, bytes: 0 };
}

/// A block's time as a date, `YYYY-MM-DD`.
pub fn chrono_date(time: u32) -> String {
    // Days since 1970 to a civil date (Howard Hinnant's algorithm).
    let days = (time / 86_400) as i64 + 719_468;
    let era = days.div_euclid(146_097);
    let doe = days.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + (month <= 2) as i64;
    format!("{year:04}-{month:02}-{day:02}")
}

#[cfg(test)]
mod tests {
    #[test]
    fn dates() {
        assert_eq!(super::chrono_date(1_231_006_505), "2009-01-03");
        assert_eq!(super::chrono_date(1_709_251_200), "2024-03-01");
    }
}
