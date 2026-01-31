
> [!WARNING]
> pdf-sign has been deprecated in favour of https://github.com/LibPDF-js/core which is a full featured PDF parsing, manipulation and signing library
> with support for LTV and PaDES compliant signing.

# @documenso/pdf-sign

This package provides functionality to sign PDF documents using various signing methods, including private keys, P12 containers, Google Cloud, USB tokens, and HTTP servers. It is designed to be used with the Documenso platform.

## Installation

To install the package, run:

```bash
npm install @documenso/pdf-sign
```

## Usage

### Signing with a Private Key

```javascript
const { signWithPrivateKey } = require('@documenso/pdf-sign');

const content = Buffer.from('...'); // PDF content
const cert = Buffer.from('...'); // Certificate in PEM format
const privateKey = Buffer.from('...'); // Private key in PEM format

const signedPdf = await signWithPrivateKey({
  content,
  cert,
  privateKey,
  // Optional fields
  signingTime: '2023-03-15T12:00:00Z', // ISO 8601 format
  timestampServer: 'http://timestamp.server',
});
```

### Signing with a P12 Container

```javascript
const { signWithP12 } = require('@documenso/pdf-sign');

const content = Buffer.from('...'); // PDF content
const p12 = Buffer.from('...'); // P12 container

const signedPdf = await signWithP12({
  content,
  cert: p12,
  // Optional fields
  password: 'p12password',
  signingTime: '2023-03-15T12:00:00Z', // ISO 8601 format
  timestampServer: 'http://timestamp.server',
});
```

### Signing with Google Cloud

```javascript
const { signWithGCloud } = require('@documenso/pdf-sign');

const content = Buffer.from('...'); // PDF content
const cert = Buffer.from('...'); // Certificate in PEM format
const keyPath = 'projects/project-id/locations/global/keyRings/keyring-name/cryptoKeys/key-name';

const signedPdf = await signWithGCloud({
  content,
  cert,
  keyPath,
  // Optional fields
  signingTime: '2023-03-15T12:00:00Z', // ISO 8601 format
  timestampServer: 'http://timestamp.server',
});
```

### Signing with USB Token

```javascript
const { signWithUsbToken } = require('@documenso/pdf-sign');

const content = Buffer.from('...'); // PDF content
const cert = Buffer.from('...'); // Certificate in PEM format
const libraryPath = '/path/to/pkcs11/library.so'; // Path to PKCS#11 library
const keyId = Buffer.from('...'); // Key ID on the token

const signedPdf = await signWithUsbToken({
  content,
  cert,
  libraryPath,
  slotId: 0, // USB token slot ID
  pin: '1234', // PIN for the USB token
  keyId,
  // Optional fields
  signingTime: '2023-03-15T12:00:00Z', // ISO 8601 format
  timestampServer: 'http://timestamp.server',
});
```

### Signing with HTTP Server

```javascript
const { signWithHttp } = require('@documenso/pdf-sign');

const content = Buffer.from('...'); // PDF content
const serverUrl = 'https://your-signing-server.com/sign';

const signedPdf = await signWithHttp({
  content,
  serverUrl,
  // Optional fields
  authToken: 'your-secure-api-token', // Bearer token for authentication
  signingTime: '2023-03-15T12:00:00Z', // ISO 8601 format
  timestampServer: 'http://timestamp.server',
});
```

## API

### `signWithPrivateKey(options)`

- `options.content` (Buffer): The PDF content to be signed.
- `options.cert` (Buffer): The certificate in PEM format.
- `options.privateKey` (Buffer): The private key in PEM format.
- `options.signingTime` (string, optional): The signing time in ISO 8601 format.
- `options.timestampServer` (string, optional): The URL of the timestamp server.

Returns a Promise that resolves to a Buffer containing the signed PDF.

### `signWithP12(options)`

- `options.content` (Buffer): The PDF content to be signed.
- `options.cert` (Buffer): The P12 container.
- `options.password` (string, optional): The password for the P12 container.
- `options.signingTime` (string, optional): The signing time in ISO 8601 format.
- `options.timestampServer` (string, optional): The URL of the timestamp server.

Returns a Promise that resolves to a Buffer containing the signed PDF.

### `signWithGCloud(options)`

- `options.content` (Buffer): The PDF content to be signed.
- `options.cert` (Buffer): The certificate in PEM format.
- `options.keyPath` (string): The Google Cloud key path.
- `options.signingTime` (string, optional): The signing time in ISO 8601 format.
- `options.timestampServer` (string, optional): The URL of the timestamp server.

Returns a Promise that resolves to a Buffer containing the signed PDF.

### `signWithUsbToken(options)`

- `options.content` (Buffer): The PDF content to be signed.
- `options.cert` (Buffer): The certificate in PEM format.
- `options.libraryPath` (string): The path to the PKCS#11 library.
- `options.slotId` (number): The USB token slot ID.
- `options.pin` (string): The PIN for the USB token.
- `options.keyId` (Buffer): The key ID on the token.
- `options.signingTime` (string, optional): The signing time in ISO 8601 format.
- `options.timestampServer` (string, optional): The URL of the timestamp server.

Returns a Promise that resolves to a Buffer containing the signed PDF.

### `signWithHttp(options)`

- `options.content` (Buffer): The PDF content to be signed.
- `options.serverUrl` (string): The URL of the HTTP signing server.
- `options.authToken` (string, optional): Bearer token for authentication.
- `options.signingTime` (string, optional): The signing time in ISO 8601 format.
- `options.timestampServer` (string, optional): The URL of the timestamp server.

Returns a Promise that resolves to a Buffer containing the signed PDF.

The HTTP signing method sends the PDF as multipart form data to the specified server URL and expects the server to return the complete CMS signed PDF data. Optional headers are included for authentication (`Authorization: Bearer <token>`), signing time (`X-Signing-Time`), and timestamp server (`X-Timestamp-Server`).

## License

This package is licensed under the [AGPL-3.0 License](LICENSE.txt).
