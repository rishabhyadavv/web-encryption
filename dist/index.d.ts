export interface Keypair {
    publicKey: string;
    privateKey: string;
}
/**
 * Generates an AES-GCM Key.
 * @returns {Promise<CryptoKey>} AES Key
 */
export declare function generateAESKey(keySize?: number): Promise<string>;
/**
 * Exports a CryptoKey to a Base64 string.
 * @param {CryptoKey} key - The AES Key to export.
 * @returns {Promise<string>} Base64-encoded key
 */
export declare function exportAESKey(key: CryptoKey): Promise<string>;
/**
 * Imports a Base64-encoded AES key.
 * @param {string} base64Key - The Base64-encoded AES Key.
 * @returns {Promise<CryptoKey>} Imported AES Key
 */
export declare function importAESKey(base64Key: string): Promise<CryptoKey>;
/**
 * Encrypts a plaintext string using AES-GCM.
 * @param {string} data - Plaintext to encrypt.
 * @param {string} keyBase64 - Base64-encoded AES key.
 * @returns {Promise<string>} Base64-encoded IV + Ciphertext
 */
export declare function encryptAES(data: string, keyBase64: string): Promise<string>;
export declare function encryptAsyncAES(data: string, keyBase64: string): Promise<string>;
/**
 * Decrypts a Base64-encoded ciphertext using AES-GCM.
 * @param {string} encryptedData - Base64-encoded IV + Ciphertext.
 * @param {string} keyBase64 - Base64-encoded AES key.
 * @returns {Promise<string>} Decrypted plaintext
 */
export declare function decryptAES(encryptedData: string, keyBase64: string): Promise<string>;
export declare function decryptAsyncAES(encryptedData: string, keyBase64: string): Promise<string>;
/**
 * Hashes a string using SHA-256.
 * @param {string} input - String to hash.
 * @returns {Promise<string>} Base64-encoded SHA-256 hash
 */
export declare function hashSHA256(input: string): Promise<string>;
/**
 * Hashes a string using SHA-512.
 * @param {string} input - String to hash.
 * @returns {Promise<string>} Base64-encoded SHA-512 hash
 */
export declare function hashSHA512(input: string): Promise<string>;
/**
 * Generates an HMAC Key.
 * @param {number} keySize - Size of the key (256 or 512 bits).
 * @returns {Promise<string>} Base64-encoded key.
 */
export declare function generateHMACKey(keySize: number): Promise<string>;
/**
 * Generates HMAC-SHA256 signature.
 * @param {string} data - The plaintext data to sign.
 * @param {string} key - Base64-encoded HMAC key.
 * @returns {Promise<string>} Base64-encoded HMAC signature.
 */
export declare function hmacSHA256(data: string, key: string): Promise<string>;
/**
 * Generates HMAC-SHA512 signature.
 */
export declare function hmacSHA512(data: string, key: string): Promise<string>;
/**
 * Generates an RSA Key Pair.
 * @returns {Promise<Keypair>} Object containing Base64-encoded public and private keys.
 */
export declare function generateRSAKeyPair(): Promise<Keypair>;
/**
 * Imports an RSA public key from a Base64-encoded string.
 * @param {string} publicKeyBase64 - Base64-encoded public key.
 * @returns {Promise<CryptoKey>} Imported public key.
 */
export declare function importRSAPublicKey(publicKeyBase64: string): Promise<CryptoKey>;
/**
 * Imports an RSA private key from a Base64-encoded string.
 * @param {string} privateKeyBase64 - Base64-encoded private key.
 * @returns {Promise<CryptoKey>} Imported private key.
 */
export declare function importRSAPrivateKey(privateKeyBase64: string): Promise<CryptoKey>;
/**
 * Encrypts data using RSA public key.
 * @param {string} data - Data to encrypt.
 * @param {string} publicKeyBase64 - Base64-encoded public key.
 * @returns {Promise<string>} Base64-encoded encrypted data.
 */
export declare function encryptRSA(data: string, publicKeyBase64: string): Promise<string>;
/**
 * Decrypts data using RSA private key.
 * @param {string} data - Base64-encoded encrypted data.
 * @param {string} privateKeyBase64 - Base64-encoded private key.
 * @returns {Promise<string>} Decrypted plaintext data.
 */
export declare function decryptRSA(data: string, privateKeyBase64: string): Promise<string>;
export declare function encryptAsyncRSA(data: string, publicKey: string): Promise<string>;
export declare function decryptAsyncRSA(data: string, privateKey: string): Promise<string>;
export declare function generateRandomString(length: number): string;
export declare function base64Encode(input: string): string;
export declare function base64Decode(input: string): string;
/**
 * Generates an ECDSA (Elliptic Curve Digital Signature Algorithm) key pair.
 * @returns {Promise<Keypair>} Object containing Base64-encoded public and private keys.
 */
export declare function generateECDSAKeyPair(): Promise<Keypair>;
/**
 * Retrieves the public key from a private ECDSA key.
 * @param {string} privateKeyBase64 - Base64-encoded ECDSA private key.
 * @returns {Promise<string>} Base64-encoded public key.
 */
export declare function getPublicECDSAKey(privateKeyBase64: string): Promise<string>;
/**
 * Signs data using an ECDSA private key.
 * @param {string} data - Data to sign.
 * @param {string} privateKeyBase64 - Base64-encoded ECDSA private key.
 * @returns {Promise<string>} Base64-encoded signature.
 */
export declare function signDataECDSA(data: string, privateKeyBase64: string): Promise<string>;
/**
 * Verifies an ECDSA signature.
 * @param {string} data - Original data.
 * @param {string} signatureBase64 - Base64-encoded signature.
 * @param {string} publicKeyBase64 - Base64-encoded ECDSA public key.
 * @returns {Promise<boolean>} True if valid, False otherwise.
 */
export declare function verifySignatureECDSA(data: string, signatureBase64: string, publicKeyBase64: string): Promise<boolean>;
