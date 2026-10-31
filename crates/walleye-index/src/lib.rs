//! Walleye index: Parquet writer (`IndexWriter`, the ingest `IndexSink`),
//! DuckDB query service (`Index`) and the filter language (`filter`).
//!
//! On-disk layout (CONTRACTS §8), inside `<capture>/index/`:
//! ```text
//! checkpoint.json      last accepted checkpoint while indexing (removed when complete)
//! manifest.json        written last by `finish`: capture row + file list ("complete")
//! frames/ flows/ dns/ http/ tls/ files/ findings/ iocs/ captures/   *.parquet
//! ```

pub mod filter;
mod index;
mod schema;
mod writer;

pub use filter::{Compiled, Expr, Param};
pub use index::{Index, MAX_LIMIT, frame_summary};
pub use writer::IndexWriter;

#[cfg(test)]
mod send_sync {
    fn assert_send_sync<T: Send + Sync>() {}
    fn assert_send<T: Send>() {}
    #[test]
    fn index_is_send_sync_and_writer_is_send() {
        assert_send_sync::<super::Index>();
        assert_send::<super::IndexWriter>();
    }
}
