use cryptographic_message_syntax::Bytes;
use gcloud_sdk::{
  google::cloud::kms::{
    self,
    v1::{key_management_service_client::KeyManagementServiceClient, AsymmetricSignRequest},
  },
  GoogleApi, GoogleAuthMiddleware,
};
use rsa::pkcs8::der::zeroize::Zeroizing;
use tokio::runtime::{self, Runtime};
use tonic::Request;
use x509_certificate::{
  algorithm, KeyInfoSigner, Sign, Signature, SignatureAlgorithm, Signer, X509CertificateError,
};

pub struct GCloudSigner {
  runtime: Runtime,
  client: GoogleApi<KeyManagementServiceClient<GoogleAuthMiddleware>>,
  key_path: String,
}

impl GCloudSigner {
  pub fn new(key_path: String) -> Self {
    let runtime = runtime::Builder::new_current_thread()
      .enable_all()
      .build()
      .expect("Failed to create runtime");

    let client = runtime.block_on(async {
      GoogleApi::from_function(
        KeyManagementServiceClient::new,
        "https://cloudkms.googleapis.com",
        None,
      )
      .await
      .expect("Failed to create Google API client")
    });

    Self {
      runtime,
      client,
      key_path,
    }
  }
}

impl KeyInfoSigner for GCloudSigner {}

impl Sign for GCloudSigner {
  fn sign(&self, message: &[u8]) -> Result<(Vec<u8>, SignatureAlgorithm), X509CertificateError> {
    let signature = self.try_sign(message)?;
    let algorithm = self.signature_algorithm()?;

    Ok((signature.into(), algorithm))
  }

  fn key_algorithm(&self) -> Option<x509_certificate::KeyAlgorithm> {
    Some(algorithm::KeyAlgorithm::Rsa)
  }

  fn signature_algorithm(&self) -> Result<SignatureAlgorithm, X509CertificateError> {
    Ok(SignatureAlgorithm::RsaSha256)
  }

  fn private_key_data(&self) -> Option<Zeroizing<Vec<u8>>> {
    None
  }

  fn public_key_data(&self) -> Bytes {
    Bytes::new()
  }

  fn rsa_primes(
    &self,
  ) -> Result<Option<(Zeroizing<Vec<u8>>, Zeroizing<Vec<u8>>)>, X509CertificateError> {
    Ok(None)
  }
}

impl Signer<Signature> for GCloudSigner {
  fn try_sign(&self, msg: &[u8]) -> Result<Signature, signature::Error> {
    let digest = sha256::Sha256Digest::digest(msg);

    let request = AsymmetricSignRequest {
      name: self.key_path.clone(),
      digest: Some(kms::v1::Digest {
        digest: Some(kms::v1::digest::Digest::Sha256(
          hex::decode(digest).expect("Failed to decode digest"),
        )),
      }),
      ..Default::default()
    };

    let mut request = Request::new(request);

    request.metadata_mut().insert(
      "x-goog-request-params",
      format!("name={}", self.key_path.clone()).parse().unwrap(),
    );

    let result = self.runtime.block_on(async {
      self
        .client
        .get()
        .asymmetric_sign(request)
        .await
        .map_err(|err| signature::Error::from_source(err))
    })?;

    let signature = result.into_inner().signature;

    Ok(Signature::from(signature))
  }
}
