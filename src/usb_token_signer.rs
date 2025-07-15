use cryptographic_message_syntax::Bytes;
use pkcs11::Ctx;
use rsa::pkcs8::der::zeroize::Zeroizing;
use std::cell::RefCell;
use x509_certificate::{
  algorithm, KeyInfoSigner, Sign, Signature, SignatureAlgorithm, Signer, X509CertificateError,
};

pub struct UsbTokenSigner {
  ctx: Ctx,
  session: pkcs11::types::CK_SESSION_HANDLE,
  key_id: Vec<u8>,
  certificate: RefCell<Option<Vec<u8>>>,
}

impl UsbTokenSigner {
  pub fn new(library_path: &str, slot_id: u64, pin: &str, key_id: Vec<u8>) -> Result<Self, Box<dyn std::error::Error>> {
    let ctx = Ctx::new_and_initialize(library_path)?;
    let slots = ctx.get_slot_list(false)?;
    let slot = slots.into_iter()
      .find(|&slot| slot == slot_id)
      .ok_or("Slot not found")?;
    
    let session = ctx.open_session(slot, pkcs11::types::CKF_SERIAL_SESSION | pkcs11::types::CKF_RW_SESSION, None, None)?;
    ctx.login(session, pkcs11::types::CKU_USER, Some(pin))?;

    Ok(Self {
      ctx,
      session,
      key_id,
      certificate: RefCell::new(None),
    })
  }

  pub fn retrieve_certificate(&self) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    if let Some(ref cert) = *self.certificate.borrow() {
      return Ok(cert.clone());
    }

    let template = vec![
      pkcs11::types::CK_ATTRIBUTE {
        attrType: pkcs11::types::CKA_CLASS,
        pValue: &pkcs11::types::CKO_CERTIFICATE as *const _ as *mut _,
        ulValueLen: std::mem::size_of::<pkcs11::types::CK_OBJECT_CLASS>() as u64,
      },
      pkcs11::types::CK_ATTRIBUTE {
        attrType: pkcs11::types::CKA_ID,
        pValue: self.key_id.as_ptr() as *mut _,
        ulValueLen: self.key_id.len() as u64,
      },
    ];

    self.ctx.find_objects_init(self.session, &template)?;
    let objects = self.ctx.find_objects(self.session, 1)?;
    self.ctx.find_objects_final(self.session)?;
    
    let cert_object = objects.first().ok_or("Certificate not found")?;

    let mut cert_template = vec![
      pkcs11::types::CK_ATTRIBUTE {
        attrType: pkcs11::types::CKA_VALUE,
        pValue: std::ptr::null_mut(),
        ulValueLen: 0,
      },
    ];

    self.ctx.get_attribute_value(self.session, *cert_object, &mut cert_template)?;
    let cert_size = cert_template[0].ulValueLen as usize;
    
    let mut cert_data = vec![0u8; cert_size];
    cert_template[0].pValue = cert_data.as_mut_ptr() as *mut _;
    
    self.ctx.get_attribute_value(self.session, *cert_object, &mut cert_template)?;
    
    *self.certificate.borrow_mut() = Some(cert_data.clone());
    Ok(cert_data)
  }
}

impl KeyInfoSigner for UsbTokenSigner {}

impl Sign for UsbTokenSigner {
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
    if let Ok(cert_data) = self.retrieve_certificate() {
      Bytes::from(cert_data)
    } else {
      Bytes::new()
    }
  }

  fn rsa_primes(
    &self,
  ) -> Result<Option<(Zeroizing<Vec<u8>>, Zeroizing<Vec<u8>>)>, X509CertificateError> {
    Ok(None)
  }
}

impl Signer<Signature> for UsbTokenSigner {
  fn try_sign(&self, msg: &[u8]) -> Result<Signature, signature::Error> {
    let digest = sha256::Sha256Digest::digest(msg);
    let digest_bytes = hex::decode(digest).map_err(|_| signature::Error::new())?;

    // Find the private key object
    let template = vec![
      pkcs11::types::CK_ATTRIBUTE {
        attrType: pkcs11::types::CKA_CLASS,
        pValue: &pkcs11::types::CKO_PRIVATE_KEY as *const _ as *mut _,
        ulValueLen: std::mem::size_of::<pkcs11::types::CK_OBJECT_CLASS>() as u64,
      },
      pkcs11::types::CK_ATTRIBUTE {
        attrType: pkcs11::types::CKA_ID,
        pValue: self.key_id.as_ptr() as *mut _,
        ulValueLen: self.key_id.len() as u64,
      },
    ];

    self.ctx.find_objects_init(self.session, &template).map_err(|_| signature::Error::new())?;
    let objects = self.ctx.find_objects(self.session, 1).map_err(|_| signature::Error::new())?;
    self.ctx.find_objects_final(self.session).map_err(|_| signature::Error::new())?;
    
    let private_key = objects.first().ok_or_else(|| signature::Error::new())?;

    // Initialize signing
    let mechanism = pkcs11::types::CK_MECHANISM {
      mechanism: pkcs11::types::CKM_RSA_PKCS,
      pParameter: std::ptr::null_mut(),
      ulParameterLen: 0,
    };

    self.ctx.sign_init(self.session, &mechanism, *private_key).map_err(|_| signature::Error::new())?;
    let signature = self.ctx.sign(self.session, &digest_bytes).map_err(|_| signature::Error::new())?;

    Ok(Signature::from(signature))
  }
}