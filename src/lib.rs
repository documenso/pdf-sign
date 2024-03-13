mod errors;
mod gcloud_signer;

use napi::bindgen_prelude::*;
use napi_derive::napi;

use chrono;
use cryptographic_message_syntax::{asn1::rfc5652, Bytes, Oid, SignedDataBuilder, SignerBuilder};
use errors::CmsError;
use gcloud_signer::GCloudSigner;
use p12::PFX;
use pem::{encode, Pem};
use x509_certificate::{CapturedX509Certificate, InMemorySigningKeyPair}; // Add the log crate for better logging

#[napi(object)]
#[derive(Default)]
pub struct SignWithPrivateKeyOptions {
  pub content: Buffer,
  pub cert: Buffer,
  pub private_key: Buffer,
  pub signing_time: Option<String>,
  pub timestamp_server: Option<String>,
}

/// Sign data with the private key.
#[napi]
pub fn sign_with_private_key(options: SignWithPrivateKeyOptions) -> Result<Buffer> {
  let SignWithPrivateKeyOptions {
    content,
    cert,
    private_key,
    signing_time,
    timestamp_server,
  } = options;

  let x509_certs = CapturedX509Certificate::from_pem_multiple(cert.to_vec())
    .map_err(|_| CmsError::CertificateParseError)?;

  let private_key_cert = InMemorySigningKeyPair::from_pkcs8_pem(&private_key)
    .map_err(|_| CmsError::PrivateKeyParseError)?;

  let mut signer = SignerBuilder::new(&private_key_cert, x509_certs.first().unwrap().clone());

  if let Some(timestamp_server) = timestamp_server {
    signer = signer
      .time_stamp_url(timestamp_server)
      .map_err(|_| CmsError::TimestampServerParseError)?;
  }

  create_signed_data(CreateSignedDataOptions {
    content,
    signer,
    signing_time,
    certs: Some(x509_certs),
  })
}

#[napi(object)]
#[derive(Default)]
pub struct SignWithP12Options {
  pub content: Buffer,
  pub cert: Buffer,
  pub password: Option<String>,
  pub signing_time: Option<String>,
  pub timestamp_server: Option<String>,
}

/// Sign data with a P12 container.
#[napi]
pub fn sign_with_p12(options: SignWithP12Options) -> Result<Buffer> {
  let SignWithP12Options {
    content,
    cert,
    password,
    signing_time,
    timestamp_server,
  } = options;

  let pfx = PFX::parse(&cert).map_err(|_| CmsError::P12ParseError)?;

  let password = password.unwrap_or(String::from(""));

  let bags = pfx
    .key_bags(&password)
    .map_err(|_| CmsError::PrivateKeyBagError)?;

  let private_key_bag = bags.first().ok_or(CmsError::NoPrivateKey)?;

  let bags = pfx
    .cert_x509_bags(&password)
    .map_err(|_| errors::CmsError::CertBagError)?;

  // Ensure that there is at least one certificate
  bags.first().ok_or(errors::CmsError::NoCertificate)?;

  // Convert the x509 bags to CapturedX509Certificate's
  let x509_certs = bags
    .iter()
    .map(|bag| {
      CapturedX509Certificate::from_pem(encode(&Pem::new("CERTIFICATE", bag.to_vec()))).unwrap()
    })
    .collect::<Vec<_>>();

  let cert = x509_certs
    .iter()
    .map(|cert| cert.encode_pem())
    .collect::<Vec<_>>()
    .join("\n");

  let private_key = encode(&Pem::new("PRIVATE KEY", private_key_bag.to_vec()));

  sign_with_private_key(SignWithPrivateKeyOptions {
    content,
    cert: Buffer::from(cert.as_bytes()),
    private_key: Buffer::from(private_key.as_bytes()),
    signing_time,
    timestamp_server,
  })
}

#[napi(object)]
#[derive(Default)]
pub struct SignWithGCloudOptions {
  pub content: Buffer,
  pub cert: Buffer,
  pub key_path: String,
  pub signing_time: Option<String>,
  pub timestamp_server: Option<String>,
}

/// Sign data with Google Cloud.
#[napi(js_name = "signWithGCloud")]
pub fn sign_with_gcloud(options: SignWithGCloudOptions) -> Result<Buffer> {
  let SignWithGCloudOptions {
    content,
    cert,
    key_path,
    signing_time,
    timestamp_server,
  } = options;

  let x509_certs = CapturedX509Certificate::from_pem_multiple(cert.to_vec())
    .map_err(|_| errors::CmsError::CertificateParseError)?;

  let gcloud_signer = GCloudSigner::new(key_path.clone());
  let mut signer = SignerBuilder::new(&gcloud_signer, x509_certs.first().unwrap().clone());

  if let Some(timestamp_server) = timestamp_server {
    signer = signer
      .time_stamp_url(timestamp_server)
      .map_err(|_| CmsError::TimestampServerParseError)?;
  }

  create_signed_data(CreateSignedDataOptions {
    content,
    signer,
    signing_time,
    certs: Some(x509_certs),
  })
}

pub struct CreateSignedDataOptions<'a> {
  pub content: Buffer,
  pub signer: SignerBuilder<'a>,
  pub signing_time: Option<String>,
  pub certs: Option<Vec<CapturedX509Certificate>>,
}

/// Helper function to create signed data.
fn create_signed_data<'a>(options: CreateSignedDataOptions<'a>) -> Result<Buffer> {
  let CreateSignedDataOptions {
    content,
    signer,
    signing_time,
    certs,
  } = options;

  let signing_time = signing_time
    .and_then(|time| time.parse::<chrono::DateTime<chrono::Utc>>().ok())
    .unwrap_or(chrono::Utc::now());

  let mut builder = SignedDataBuilder::default()
    .content_type(Oid(Bytes::from(rfc5652::OID_ID_DATA.as_ref())))
    .content_external(content.to_vec())
    .signing_time(signing_time.into())
    .signer(signer);

  if let Some(certs) = certs {
    builder = builder.certificates(certs.into_iter());
  }

  builder
    .build_der()
    .map_err(|_| CmsError::BuildSignedDataError.into())
    .map(|data| Buffer::from(data))
}
