use thiserror::Error;

#[derive(Error, Debug)]
pub enum PolicyError {
    #[error("Invalid policy: {0}")]
    InvalidPolicy(String),
    #[error("Key management error: {0}")]
    KeyManagement(String),
    #[error("Descriptor generation error: {0}")]
    DescriptorGeneration(String),
    #[error("Liana integration error: {0}")]
    LianaIntegration(String),
}
