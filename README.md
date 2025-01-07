# **WebEncryption Library Documentation**

## 📚 **Introduction**

**WebEncryption** is a JavaScript/TypeScript library designed for cryptographic operations, including **AES encryption**, **RSA encryption**, **ECDSA key pair generation**, **HMAC signature generation**, and **hashing**. This library leverages the **Web Crypto API** to provide secure and performant encryption functionalities.

---

## 🚀 **Installation**

Using **npm**:

```bash
npm install web-secure-encryption
```

Using **yarn**:

```bash
yarn add web-secure-encryption
```

---

## 🛠️ **Methods Overview**

### ✅ **AES Encryption and Decryption**

#### **generateAESKey**
Generates an AES-GCM encryption key.

```typescript
generateAESKey(keySize: number = 256): Promise<string>
```

- **keySize:** AES key size (128, 192, 256)
- **Returns:** Base64-encoded AES Key.

#### **encryptAES**
Encrypts a string using AES-GCM.

```typescript
encryptAES(data: string, keyBase64: string): Promise<string>
```

- **data:** Plaintext to encrypt.
- **keyBase64:** Base64-encoded AES key.
- **Returns:** Base64-encoded IV + Ciphertext.

#### **decryptAES**
Decrypts a Base64-encoded ciphertext using AES-GCM.

```typescript
decryptAES(encryptedData: string, keyBase64: string): Promise<string>
```

- **encryptedData:** Base64-encoded ciphertext.
- **keyBase64:** Base64-encoded AES key.
- **Returns:** Decrypted plaintext.

---

### ✅ **Hashing**

#### **hashSHA256**
Generates a SHA-256 hash.

```typescript
hashSHA256(input: string): Promise<string>
```

- **input:** String to hash.
- **Returns:** Base64-encoded SHA-256 hash.

#### **hashSHA512**
Generates a SHA-512 hash.

```typescript
hashSHA512(input: string): Promise<string>
```

- **input:** String to hash.
- **Returns:** Base64-encoded SHA-512 hash.

---

### ✅ **HMAC Signatures**

#### **generateHMACKey**
Generates an HMAC key.

```typescript
generateHMACKey(keySize: number): Promise<string>
```

- **keySize:** Size of the key (256 or 512 bits).
- **Returns:** Base64-encoded HMAC key.

#### **hmacSHA256**
Generates an HMAC-SHA256 signature.

```typescript
hmacSHA256(data: string, key: string): Promise<string>
```

- **data:** Data to sign.
- **key:** Base64-encoded HMAC key.
- **Returns:** Base64-encoded HMAC signature.

#### **hmacSHA512**
Generates an HMAC-SHA512 signature.

```typescript
hmacSHA512(data: string, key: string): Promise<string>
```

- **data:** Data to sign.
- **key:** Base64-encoded HMAC key.
- **Returns:** Base64-encoded HMAC signature.

---

### ✅ **RSA Encryption and Decryption**

#### **generateRSAKeyPair**
Generates an RSA Key Pair.

```typescript
generateRSAKeyPair(): Promise<Keypair>
```

- **Returns:** Object containing Base64-encoded public and private keys.

#### **encryptRSA**
Encrypts data using an RSA public key.

```typescript
encryptRSA(data: string, publicKeyBase64: string): Promise<string>
```

- **data:** Data to encrypt.
- **publicKeyBase64:** Base64-encoded RSA public key.
- **Returns:** Base64-encoded encrypted data.

#### **decryptRSA**
Decrypts data using an RSA private key.

```typescript
decryptRSA(data: string, privateKeyBase64: string): Promise<string>
```

- **data:** Encrypted data.
- **privateKeyBase64:** Base64-encoded RSA private key.
- **Returns:** Decrypted plaintext.

#### **importRSAPublicKey**
Imports an RSA public key.

```typescript
importRSAPublicKey(publicKeyBase64: string): Promise<CryptoKey>
```

- **publicKeyBase64:** Base64-encoded RSA public key.
- **Returns:** Imported RSA public key.

#### **importRSAPrivateKey**
Imports an RSA private key.

```typescript
importRSAPrivateKey(privateKeyBase64: string): Promise<CryptoKey>
```

- **privateKeyBase64:** Base64-encoded RSA private key.
- **Returns:** Imported RSA private key.

---

### ✅ **ECDSA (Elliptic Curve Digital Signature Algorithm)**

#### **generateECDSAKeyPair**
Generates an ECDSA Key Pair.

```typescript
generateECDSAKeyPair(): Promise<Keypair>
```

- **Returns:** Object containing Base64-encoded public and private keys.

#### **getPublicECDSAKey**
Extracts the public key from a private ECDSA key.

```typescript
getPublicECDSAKey(privateKeyBase64: string): Promise<string>
```

- **privateKeyBase64:** Base64-encoded private key.
- **Returns:** Base64-encoded public key.

#### **signDataECDSA**
Signs data using an ECDSA private key.

```typescript
signDataECDSA(data: string, privateKeyBase64: string): Promise<string>
```

- **data:** Data to sign.
- **privateKeyBase64:** Base64-encoded private key.
- **Returns:** Base64-encoded signature.

#### **verifySignatureECDSA**
Verifies an ECDSA signature.

```typescript
verifySignatureECDSA(data: string, signatureBase64: string, publicKeyBase64: string): Promise<boolean>
```

- **data:** Original data.
- **signatureBase64:** Base64-encoded signature.
- **publicKeyBase64:** Base64-encoded public key.
- **Returns:** `true` if the signature is valid.

---

### ✅ **Utilities**

#### **generateRandomString**
Generates a random string of a specified length.

```typescript
generateRandomString(length: number): string
```

- **length:** Length of the random string.
- **Returns:** Random string.

#### **base64Encode**
Encodes a string in Base64.

```typescript
base64Encode(input: string): string
```

- **input:** String to encode.
- **Returns:** Base64-encoded string.

#### **base64Decode**
Decodes a Base64-encoded string.

```typescript
base64Decode(input: string): string
```

- **input:** Base64-encoded string.
- **Returns:** Decoded string.

---


## 📝 **License**

MIT
