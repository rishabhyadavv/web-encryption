
export interface Keypair {
  publicKey: string;
  privateKey: string;
}

  // ---------------------------------------------
  // ✅ AES Key Management
  // ---------------------------------------------

  /**
   * Generates an AES-GCM Key.
   * @returns {Promise<CryptoKey>} AES Key
   */
  export async function generateAESKey(keySize: number = 256): Promise<string> {
    if (![256, 128,192].includes(keySize)) {
      throw new Error("Invalid key size. Must be 128,192 or 256 bits.");
    }
    let key = await crypto.subtle.generateKey(
        {
          name: "AES-GCM",
          length: keySize,
        },
        true,
        ["encrypt", "decrypt"]
      );
      return exportAESKey(key);
  }
  
  /**
   * Exports a CryptoKey to a Base64 string.
   * @param {CryptoKey} key - The AES Key to export.
   * @returns {Promise<string>} Base64-encoded key
   */
  export async function exportAESKey(key: CryptoKey): Promise<string> {
    const exported = await crypto.subtle.exportKey("raw", key);
    return btoa(String.fromCharCode(...new Uint8Array(exported)));
  }

  /**
   * Imports a Base64-encoded AES key.
   * @param {string} base64Key - The Base64-encoded AES Key.
   * @returns {Promise<CryptoKey>} Imported AES Key
   */
  export async function importAESKey(base64Key: string): Promise<CryptoKey> {
    const keyBytes = Uint8Array.from(atob(base64Key), (c) => c.charCodeAt(0));
    return await crypto.subtle.importKey(
      "raw",
      keyBytes,
      { name: "AES-GCM" },
      false,
      ["encrypt", "decrypt"]
    );
  }

  // ---------------------------------------------
  // ✅ AES Encryption and Decryption
  // ---------------------------------------------

  /**
   * Encrypts a plaintext string using AES-GCM.
   * @param {string} data - Plaintext to encrypt.
   * @param {string} keyBase64 - Base64-encoded AES key.
   * @returns {Promise<string>} Base64-encoded IV + Ciphertext
   */
  export async function encryptAES(
    data: string,
    keyBase64: string
  ): Promise<string> {
    const key = await importAESKey(keyBase64);

    const iv = crypto.getRandomValues(new Uint8Array(12));
    const encodedData = new TextEncoder().encode(data);

    const encrypted = await crypto.subtle.encrypt(
      {
        name: "AES-GCM",
        iv: iv,
      },
      key,
      encodedData
    );

    const combined = new Uint8Array([...iv, ...new Uint8Array(encrypted)]);
    return btoa(String.fromCharCode(...combined));
  }

  export async function encryptAsyncAES(
    data: string,
    keyBase64: string
  ): Promise<string> {
    return await encryptAES(data, keyBase64);
  }

  /**
   * Decrypts a Base64-encoded ciphertext using AES-GCM.
   * @param {string} encryptedData - Base64-encoded IV + Ciphertext.
   * @param {string} keyBase64 - Base64-encoded AES key.
   * @returns {Promise<string>} Decrypted plaintext
   */
  export async function decryptAES(
    encryptedData: string,
    keyBase64: string
  ): Promise<string> {
    const key = await importAESKey(keyBase64);

    const decodedData = Uint8Array.from(atob(encryptedData), (c) =>
      c.charCodeAt(0)
    );
    const iv = decodedData.slice(0, 12);
    const ciphertext = decodedData.slice(12);

    const decrypted = await crypto.subtle.decrypt(
      {
        name: "AES-GCM",
        iv: iv,
      },
      key,
      ciphertext
    );

    return new TextDecoder().decode(decrypted);
  }

  export async function decryptAsyncAES(
    encryptedData: string,
    keyBase64: string
  ): Promise<string> {
    return await decryptAES(encryptedData, keyBase64);
  }

  // ---------------------------------------------
  // ✅ Hashing (SHA256 & SHA512)
  // ---------------------------------------------

  /**
   * Hashes a string using SHA-256.
   * @param {string} input - String to hash.
   * @returns {Promise<string>} Base64-encoded SHA-256 hash
   */
  export async function hashSHA256(input: string): Promise<string> {
    const data = new TextEncoder().encode(input);
    const hashBuffer = await crypto.subtle.digest("SHA-256", data);
    return btoa(String.fromCharCode(...new Uint8Array(hashBuffer)));
  }

  /**
   * Hashes a string using SHA-512.
   * @param {string} input - String to hash.
   * @returns {Promise<string>} Base64-encoded SHA-512 hash
   */
  export async function hashSHA512(input: string): Promise<string> {
    const data = new TextEncoder().encode(input);
    const hashBuffer = await crypto.subtle.digest("SHA-512", data);
    return btoa(String.fromCharCode(...new Uint8Array(hashBuffer)));
  }

  // ---------------------------------------------
  // ✅ HMAC (SHA256 & SHA512)
  // ---------------------------------------------

  /**
   * Generates an HMAC Key.
   * @param {number} keySize - Size of the key (256 or 512 bits).
   * @returns {Promise<string>} Base64-encoded key.
   */
  export async function generateHMACKey(keySize: number): Promise<string> {
    if (![256, 512].includes(keySize)) {
      throw new Error("Invalid key size. Must be 256 or 512 bits.");
    }

    const key = await crypto.subtle.generateKey(
      {
        name: "HMAC",
        hash: { name: keySize === 256 ? "SHA-256" : "SHA-512" },
      },
      true, // Extractable
      ["sign", "verify"]
    );

    const exportedKey = await crypto.subtle.exportKey("raw", key);
    return btoa(String.fromCharCode(...new Uint8Array(exportedKey)));
  }

  /**
   * Generates HMAC-SHA256 signature.
   * @param {string} data - The plaintext data to sign.
   * @param {string} key - Base64-encoded HMAC key.
   * @returns {Promise<string>} Base64-encoded HMAC signature.
   */
  export async function hmacSHA256(data: string, key: string): Promise<string> {
    try {
      // Decode the Base64-encoded key
      const keyBytes = Uint8Array.from(atob(key), (c) => c.charCodeAt(0));

      // Import the key specifically for HMAC
      const cryptoKey = await crypto.subtle.importKey(
        "raw",
        keyBytes,
        { name: "HMAC", hash: { name: "SHA-256" } },
        false,
        ["sign"]
      );

      // Create HMAC Signature
      const signature = await crypto.subtle.sign(
        "HMAC",
        cryptoKey,
        new TextEncoder().encode(data)
      );

      // Return the signature as a Base64 string
      return btoa(String.fromCharCode(...new Uint8Array(signature)));
    } catch (error) {
      console.error("HMAC-SHA256 Error:", error);
      throw new Error(`Failed to generate HMAC-SHA256 signature: ${error}`);
    }
  }

  /**
   * Generates HMAC-SHA512 signature.
   */
  export async function hmacSHA512(data: string, key: string): Promise<string> {
    const cryptoKey = await importAESKey(key);
    const signature = await crypto.subtle.sign(
      "HMAC",
      cryptoKey,
      new TextEncoder().encode(data)
    );
    return btoa(String.fromCharCode(...new Uint8Array(signature)));
  }

  // ---------------------------------------------
  // ✅ RSA Encryption & Decryption
  // ---------------------------------------------

  /**
   * Generates an RSA Key Pair.
   * @returns {Promise<Keypair>} Object containing Base64-encoded public and private keys.
   */
  export async function generateRSAKeyPair(): Promise<Keypair> {
    const keyPair = await crypto.subtle.generateKey(
      {
        name: "RSA-OAEP",
        modulusLength: 2048,
        publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
        hash: "SHA-256",
      },
      true, // Keys are extractable
      ["encrypt", "decrypt"]
    );

    // Export the public key
    const publicKeyBuffer = await crypto.subtle.exportKey(
      "spki",
      keyPair.publicKey
    );
    const publicKeyBase64 = btoa(
      String.fromCharCode(...new Uint8Array(publicKeyBuffer))
    );

    // Export the private key
    const privateKeyBuffer = await crypto.subtle.exportKey(
      "pkcs8",
      keyPair.privateKey
    );
    const privateKeyBase64 = btoa(
      String.fromCharCode(...new Uint8Array(privateKeyBuffer))
    );

    return {
      publicKey: publicKeyBase64,
      privateKey: privateKeyBase64,
    };
  }

  /**
   * Imports an RSA public key from a Base64-encoded string.
   * @param {string} publicKeyBase64 - Base64-encoded public key.
   * @returns {Promise<CryptoKey>} Imported public key.
   */
  export async function importRSAPublicKey(
    publicKeyBase64: string
  ): Promise<CryptoKey> {
    const publicKeyBuffer = Uint8Array.from(atob(publicKeyBase64), (c) =>
      c.charCodeAt(0)
    );
    return await crypto.subtle.importKey(
      "spki",
      publicKeyBuffer,
      { name: "RSA-OAEP", hash: "SHA-256" },
      false,
      ["encrypt"]
    );
  }

  /**
   * Imports an RSA private key from a Base64-encoded string.
   * @param {string} privateKeyBase64 - Base64-encoded private key.
   * @returns {Promise<CryptoKey>} Imported private key.
   */
  export async function importRSAPrivateKey(
    privateKeyBase64: string
  ): Promise<CryptoKey> {
    const privateKeyBuffer = Uint8Array.from(atob(privateKeyBase64), (c) =>
      c.charCodeAt(0)
    );
    return await crypto.subtle.importKey(
      "pkcs8",
      privateKeyBuffer,
      { name: "RSA-OAEP", hash: "SHA-256" },
      false,
      ["decrypt"]
    );
  }

  /**
   * Encrypts data using RSA public key.
   * @param {string} data - Data to encrypt.
   * @param {string} publicKeyBase64 - Base64-encoded public key.
   * @returns {Promise<string>} Base64-encoded encrypted data.
   */
  export async function encryptRSA(
    data: string,
    publicKeyBase64: string
  ): Promise<string> {
    const publicKey = await importRSAPublicKey(publicKeyBase64);
    const encrypted = await crypto.subtle.encrypt(
      { name: "RSA-OAEP" },
      publicKey,
      new TextEncoder().encode(data)
    );
    return btoa(String.fromCharCode(...new Uint8Array(encrypted)));
  }

  /**
   * Decrypts data using RSA private key.
   * @param {string} data - Base64-encoded encrypted data.
   * @param {string} privateKeyBase64 - Base64-encoded private key.
   * @returns {Promise<string>} Decrypted plaintext data.
   */
  export async function decryptRSA(
    data: string,
    privateKeyBase64: string
  ): Promise<string> {
    const privateKey = await importRSAPrivateKey(privateKeyBase64);
    const decrypted = await crypto.subtle.decrypt(
      { name: "RSA-OAEP" },
      privateKey,
      Uint8Array.from(atob(data), (c) => c.charCodeAt(0))
    );
    return new TextDecoder().decode(decrypted);
  }

  export async function encryptAsyncRSA(
    data: string,
    publicKey: string
  ): Promise<string> {
    return await encryptRSA(data, publicKey);
  }

  export async function decryptAsyncRSA(
    data: string,
    privateKey: string
  ): Promise<string> {
    return await decryptRSA(data, privateKey);
  }

  export function generateRandomString(length: number): string {
    return crypto.getRandomValues(new Uint8Array(length)).join("");
  }

  export function base64Encode(input: string): string {
    return btoa(input);
  }

  export function base64Decode(input: string): string {
    return atob(input);
  }

  /**
   * Generates an ECDSA (Elliptic Curve Digital Signature Algorithm) key pair.
   * @returns {Promise<Keypair>} Object containing Base64-encoded public and private keys.
   */
  export async function generateECDSAKeyPair(): Promise<Keypair> {
    try {
      // Generate ECDSA Key Pair
      const keyPair = await crypto.subtle.generateKey(
        {
          name: "ECDSA",
          namedCurve: "P-256", // Recommended curve for ECDSA
        },
        true, // Keys are extractable
        ["sign", "verify"] // Usage for private and public keys
      );

      // Export Public Key
      const publicKeyBuffer = await crypto.subtle.exportKey(
        "spki",
        keyPair.publicKey
      );
      const publicKeyBase64 = btoa(
        String.fromCharCode(...new Uint8Array(publicKeyBuffer))
      );

      // Export Private Key
      const privateKeyBuffer = await crypto.subtle.exportKey(
        "pkcs8",
        keyPair.privateKey
      );
      const privateKeyBase64 = btoa(
        String.fromCharCode(...new Uint8Array(privateKeyBuffer))
      );

      return {
        publicKey: publicKeyBase64,
        privateKey: privateKeyBase64,
      };
    } catch (error) {
      console.error("ECDSA Key Pair Generation Error:", error);
      throw new Error(`Failed to generate ECDSA key pair: ${error}`);
    }
  }

  /**
   * Retrieves the public key from a private ECDSA key.
   * @param {string} privateKeyBase64 - Base64-encoded ECDSA private key.
   * @returns {Promise<string>} Base64-encoded public key.
   */
  export async function getPublicECDSAKey(
    privateKeyBase64: string
  ): Promise<string> {
    try {
      // Decode Private Key
      const privateKeyBuffer = Uint8Array.from(atob(privateKeyBase64), (c) =>
        c.charCodeAt(0)
      );
      const privateKey = await crypto.subtle.importKey(
        "pkcs8",
        privateKeyBuffer,
        { name: "ECDSA", namedCurve: "P-256" },
        true,
        ["sign"]
      );

      // Extract Public Key
      const publicKey = await crypto.subtle.exportKey("spki", privateKey);

      return btoa(String.fromCharCode(...new Uint8Array(publicKey)));
    } catch (error) {
      console.error("Failed to extract public key from private key:", error);
      throw new Error(`Failed to extract public key: ${error}`);
    }
  }

  /**
   * Signs data using an ECDSA private key.
   * @param {string} data - Data to sign.
   * @param {string} privateKeyBase64 - Base64-encoded ECDSA private key.
   * @returns {Promise<string>} Base64-encoded signature.
   */
  export async function signDataECDSA(
    data: string,
    privateKeyBase64: string
  ): Promise<string> {
    try {
      // Decode Private Key
      const privateKeyBuffer = Uint8Array.from(atob(privateKeyBase64), (c) =>
        c.charCodeAt(0)
      );
      const privateKey = await crypto.subtle.importKey(
        "pkcs8",
        privateKeyBuffer,
        { name: "ECDSA", namedCurve: "P-256" },
        false,
        ["sign"]
      );

      // Sign Data
      const signature = await crypto.subtle.sign(
        {
          name: "ECDSA",
          hash: { name: "SHA-256" },
        },
        privateKey,
        new TextEncoder().encode(data)
      );

      return btoa(String.fromCharCode(...new Uint8Array(signature)));
    } catch (error) {
      console.error("Failed to sign data:", error);
      throw new Error(`Failed to sign data: ${error}`);
    }
  }

  /**
   * Verifies an ECDSA signature.
   * @param {string} data - Original data.
   * @param {string} signatureBase64 - Base64-encoded signature.
   * @param {string} publicKeyBase64 - Base64-encoded ECDSA public key.
   * @returns {Promise<boolean>} True if valid, False otherwise.
   */
  export async function verifySignatureECDSA(
    data: string,
    signatureBase64: string,
    publicKeyBase64: string
  ): Promise<boolean> {
    try {
      // Decode Public Key
      const publicKeyBuffer = Uint8Array.from(atob(publicKeyBase64), (c) =>
        c.charCodeAt(0)
      );
      const publicKey = await crypto.subtle.importKey(
        "spki",
        publicKeyBuffer,
        { name: "ECDSA", namedCurve: "P-256" },
        false,
        ["verify"]
      );

      // Decode Signature
      const signatureBuffer = Uint8Array.from(atob(signatureBase64), (c) =>
        c.charCodeAt(0)
      );

      // Verify Signature
      return await crypto.subtle.verify(
        {
          name: "ECDSA",
          hash: { name: "SHA-256" },
        },
        publicKey,
        signatureBuffer,
        new TextEncoder().encode(data)
      );
    } catch (error) {
      console.error("Failed to verify signature:", error);
      throw new Error(`Failed to verify signature: ${error}`);
    }
  }


