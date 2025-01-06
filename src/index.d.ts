/** Represents an RSA or ECDSA Keypair with public and private keys. */
export interface Keypair {
    publicKey: string;
    privateKey: string;
  }
  
  // ---------------------------------------------
  // ✅ AES Key Management
  // ---------------------------------------------
  
  /** Generates an AES-GCM Key (128, 192, or 256 bits). */
  export function generateAESKey(keySize?: number): Promise<string>;
  
  /** Exports a CryptoKey to a Base64 string. */
  export function exportAESKey(key: CryptoKey): Promise<string>;
  
  /** Imports a Base64-encoded AES Key. */
  export function importAESKey(base64Key: string): Promise<CryptoKey>;
  
  // ---------------------------------------------
  // ✅ AES Encryption and Decryption
  // ---------------------------------------------
  
  /** Encrypts a plaintext string using AES-GCM. */
  export function encryptAES(data: string, keyBase64: string): Promise<string>;
  
  /** Asynchronously encrypts a plaintext string using AES-GCM. */
  export function encryptAsyncAES(data: string, keyBase64: string): Promise<string>;
  
  /** Decrypts AES-GCM encrypted data. */
  export function decryptAES(encryptedData: string, keyBase64: string): Promise<string>;
  
  /** Asynchronously decrypts AES-GCM encrypted data. */
  export function decryptAsyncAES(encryptedData: string, keyBase64: string): Promise<string>;
  
  // ---------------------------------------------
  // ✅ Hashing (SHA256 & SHA512)
  // ---------------------------------------------
  
  /** Generates a SHA-256 hash of the input string. */
  export function hashSHA256(input: string): Promise<string>;
  
  /** Generates a SHA-512 hash of the input string. */
  export function hashSHA512(input: string): Promise<string>;
  
  // ---------------------------------------------
  // ✅ HMAC (SHA256 & SHA512)
  // ---------------------------------------------
  
  /** Generates an HMAC key (256 or 512 bits). */
  export function generateHMACKey(keySize: number): Promise<string>;
  
  /** Generates an HMAC-SHA256 signature. */
  export function hmacSHA256(data: string, key: string): Promise<string>;
  
  /** Generates an HMAC-SHA512 signature. */
  export function hmacSHA512(data: string, key: string): Promise<string>;
  
  // ---------------------------------------------
  // ✅ RSA Encryption & Decryption
  // ---------------------------------------------
  
  /** Generates an RSA Key Pair (2048-bit keys). */
  export function generateRSAKeyPair(): Promise<Keypair>;
  
  /** Imports an RSA Public Key from a Base64-encoded string. */
  export function importRSAPublicKey(publicKeyBase64: string): Promise<CryptoKey>;
  
  /** Imports an RSA Private Key from a Base64-encoded string. */
  export function importRSAPrivateKey(privateKeyBase64: string): Promise<CryptoKey>;
  
  /** Encrypts data using an RSA Public Key. */
  export function encryptRSA(data: string, publicKeyBase64: string): Promise<string>;
  
  /** Asynchronously encrypts data using an RSA Public Key. */
  export function encryptAsyncRSA(data: string, publicKey: string): Promise<string>;
  
  /** Decrypts data using an RSA Private Key. */
  export function decryptRSA(data: string, privateKeyBase64: string): Promise<string>;
  
  /** Asynchronously decrypts data using an RSA Private Key. */
  export function decryptAsyncRSA(data: string, privateKey: string): Promise<string>;
  
  /** Retrieves the Public Key from an RSA Private Key. */
  export function getPublicRSAKey(privateKeyBase64: string): Promise<string>;
  
  // ---------------------------------------------
  // ✅ ECDSA Key Management
  // ---------------------------------------------
  
  /** Generates an ECDSA (P-256 curve) Key Pair. */
  export function generateECDSAKeyPair(): Promise<Keypair>;
  
  /** Retrieves the Public Key from an ECDSA Private Key. */
  export function getPublicECDSAKey(privateKeyBase64: string): Promise<string>;
  
  /** Signs data using an ECDSA Private Key. */
  export function signDataECDSA(data: string, privateKeyBase64: string): Promise<string>;
  
  /** Verifies an ECDSA signature using a Public Key. */
  export function verifySignatureECDSA(
    data: string,
    signatureBase64: string,
    publicKeyBase64: string
  ): Promise<boolean>;
  
  // ---------------------------------------------
  // ✅ Utility Functions
  // ---------------------------------------------
  
  /** Generates a random string of a given length. */
  export function generateRandomString(length: number): string;
  
  /** Encodes a string in Base64 format. */
  export function base64Encode(input: string): string;
  
  /** Decodes a Base64-encoded string. */
  export function base64Decode(input: string): string;
  