use reqwest;
use napi::bindgen_prelude::*;

pub struct HttpSigner {
    server_url: String,
    auth_token: Option<String>,
}

impl HttpSigner {
    pub fn new(server_url: String, auth_token: Option<String>) -> Self {
        HttpSigner { server_url, auth_token }
    }

    pub async fn sign_pdf(&self, content: &[u8], signing_time: Option<String>, timestamp_server: Option<String>) -> Result<Vec<u8>> {
        let client = reqwest::Client::new();
        
        let form = reqwest::multipart::Form::new()
            .part("pdf", reqwest::multipart::Part::bytes(content.to_vec())
                .file_name("document.pdf")
                .mime_str("application/pdf")
                .map_err(|_| Error::from_reason("Failed to create multipart form".to_string()))?);

        let mut request = client
            .post(&self.server_url)
            .multipart(form);

        if let Some(auth_token) = &self.auth_token {
            request = request.header("Authorization", format!("Bearer {}", auth_token));
        }

        if let Some(signing_time) = signing_time {
            request = request.header("X-Signing-Time", signing_time);
        }

        if let Some(timestamp_server) = timestamp_server {
            request = request.header("X-Timestamp-Server", timestamp_server);
        }

        let response = request
            .send()
            .await
            .map_err(|_| Error::from_reason("HTTP request failed".to_string()))?;

        if !response.status().is_success() {
            return Err(Error::from_reason(format!("HTTP request failed with status: {}", response.status())));
        }

        let signed_pdf = response
            .bytes()
            .await
            .map_err(|_| Error::from_reason("Failed to read response body".to_string()))?;

        Ok(signed_pdf.to_vec())
    }
}