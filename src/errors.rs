use std::fmt;

#[derive(Debug)]
pub enum CmsError {
  CertificateParseError,
  PrivateKeyParseError,
  P12ParseError,
  PrivateKeyBagError,
  NoPrivateKey,
  CertBagError,
  NoCertificate,
  TimestampServerParseError,
  BuildSignedDataError,
  DigestError,
}

impl std::error::Error for CmsError {}

impl From<CmsError> for napi::Error {
  fn from(error: CmsError) -> Self {
    napi::Error::from_reason(error.to_string())
  }
}

impl fmt::Display for CmsError {
  fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
    match *self {
      CmsError::CertificateParseError => write!(f, "Failed to parse certificate"),
      CmsError::PrivateKeyParseError => write!(f, "Failed to parse private key"),
      CmsError::P12ParseError => write!(f, "Failed to parse p12"),
      CmsError::PrivateKeyBagError => write!(f, "Failed to get private key bags"),
      CmsError::NoPrivateKey => write!(f, "No private key bags"),
      CmsError::CertBagError => write!(f, "Failed to get cert bags"),
      CmsError::NoCertificate => write!(f, "No cert bags"),
      CmsError::TimestampServerParseError => write!(f, "Failed to parse timestamp server"),
      CmsError::BuildSignedDataError => write!(f, "Failed to build signed data"),
      CmsError::DigestError => write!(f, "Failed to get digest"),
    }
  }
}
