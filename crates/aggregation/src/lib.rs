pub mod aggregator;
pub mod types;

pub use aggregator::{AggregationError, ProofAggregator};
pub use types::{AggregatedProof, AggregationStrategy, IndividualProof, ProofSystemId};
