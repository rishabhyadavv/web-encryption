async function t(t=256){if(![256,128,192].includes(t))throw new Error("Invalid key size. Must be 128,192 or 256 bits.");return r(await crypto.subtle.generateKey({name:"AES-GCM",length:t},!0,["encrypt","decrypt"]))}async function r(t){const r=await crypto.subtle.exportKey("raw",t);return btoa(String.fromCharCode(...new Uint8Array(r)))}async function e(t){const r=Uint8Array.from(atob(t),(t=>t.charCodeAt(0)));return await crypto.subtle.importKey("raw",r,{name:"AES-GCM"},!1,["encrypt","decrypt"])}async function n(t,r){const n=await e(r),a=crypto.getRandomValues(new Uint8Array(12)),o=(new TextEncoder).encode(t),i=await crypto.subtle.encrypt({name:"AES-GCM",iv:a},n,o),c=new Uint8Array([...a,...new Uint8Array(i)]);return btoa(String.fromCharCode(...c))}async function a(t,r){return await n(t,r)}async function o(t,r){const n=await e(r),a=Uint8Array.from(atob(t),(t=>t.charCodeAt(0))),o=a.slice(0,12),i=a.slice(12),c=await crypto.subtle.decrypt({name:"AES-GCM",iv:o},n,i);return(new TextDecoder).decode(c)}async function i(t,r){return await o(t,r)}async function c(t){const r=(new TextEncoder).encode(t),e=await crypto.subtle.digest("SHA-256",r);return btoa(String.fromCharCode(...new Uint8Array(e)))}async function y(t){const r=(new TextEncoder).encode(t),e=await crypto.subtle.digest("SHA-512",r);return btoa(String.fromCharCode(...new Uint8Array(e)))}async function s(t){if(![256,512].includes(t))throw new Error("Invalid key size. Must be 256 or 512 bits.");const r=await crypto.subtle.generateKey({name:"HMAC",hash:{name:256===t?"SHA-256":"SHA-512"}},!0,["sign","verify"]),e=await crypto.subtle.exportKey("raw",r);return btoa(String.fromCharCode(...new Uint8Array(e)))}async function u(t,r){try{const e=Uint8Array.from(atob(r),(t=>t.charCodeAt(0))),n=await crypto.subtle.importKey("raw",e,{name:"HMAC",hash:{name:"SHA-256"}},!1,["sign"]),a=await crypto.subtle.sign("HMAC",n,(new TextEncoder).encode(t));return btoa(String.fromCharCode(...new Uint8Array(a)))}catch(t){throw console.error("HMAC-SHA256 Error:",t),new Error(`Failed to generate HMAC-SHA256 signature: ${t}`)}}async function w(t,r){const n=await e(r),a=await crypto.subtle.sign("HMAC",n,(new TextEncoder).encode(t));return btoa(String.fromCharCode(...new Uint8Array(a)))}async function p(){const t=await crypto.subtle.generateKey({name:"RSA-OAEP",modulusLength:2048,publicExponent:new Uint8Array([1,0,1]),hash:"SHA-256"},!0,["encrypt","decrypt"]),r=await crypto.subtle.exportKey("spki",t.publicKey),e=btoa(String.fromCharCode(...new Uint8Array(r))),n=await crypto.subtle.exportKey("pkcs8",t.privateKey);return{publicKey:e,privateKey:btoa(String.fromCharCode(...new Uint8Array(n)))}}async function A(t){const r=Uint8Array.from(atob(t),(t=>t.charCodeAt(0)));return await crypto.subtle.importKey("spki",r,{name:"RSA-OAEP",hash:"SHA-256"},!1,["encrypt"])}async function d(t){const r=Uint8Array.from(atob(t),(t=>t.charCodeAt(0)));return await crypto.subtle.importKey("pkcs8",r,{name:"RSA-OAEP",hash:"SHA-256"},!1,["decrypt"])}async function b(t,r){const e=await A(r),n=await crypto.subtle.encrypt({name:"RSA-OAEP"},e,(new TextEncoder).encode(t));return btoa(String.fromCharCode(...new Uint8Array(n)))}async function m(t,r){const e=await d(r),n=await crypto.subtle.decrypt({name:"RSA-OAEP"},e,Uint8Array.from(atob(t),(t=>t.charCodeAt(0))));return(new TextDecoder).decode(n)}async function C(t,r){return await b(t,r)}async function f(t,r){return await m(t,r)}function l(t){return crypto.getRandomValues(new Uint8Array(t)).join("")}function h(t){return btoa(t)}function S(t){return atob(t)}async function g(){try{const t=await crypto.subtle.generateKey({name:"ECDSA",namedCurve:"P-256"},!0,["sign","verify"]),r=await crypto.subtle.exportKey("spki",t.publicKey),e=btoa(String.fromCharCode(...new Uint8Array(r))),n=await crypto.subtle.exportKey("pkcs8",t.privateKey);return{publicKey:e,privateKey:btoa(String.fromCharCode(...new Uint8Array(n)))}}catch(t){throw console.error("ECDSA Key Pair Generation Error:",t),new Error(`Failed to generate ECDSA key pair: ${t}`)}}async function E(t){try{const r=Uint8Array.from(atob(t),(t=>t.charCodeAt(0))),e=await crypto.subtle.importKey("pkcs8",r,{name:"ECDSA",namedCurve:"P-256"},!0,["sign"]),n=await crypto.subtle.exportKey("spki",e);return btoa(String.fromCharCode(...new Uint8Array(n)))}catch(t){throw console.error("Failed to extract public key from private key:",t),new Error(`Failed to extract public key: ${t}`)}}async function U(t,r){try{const e=Uint8Array.from(atob(r),(t=>t.charCodeAt(0))),n=await crypto.subtle.importKey("pkcs8",e,{name:"ECDSA",namedCurve:"P-256"},!1,["sign"]),a=await crypto.subtle.sign({name:"ECDSA",hash:{name:"SHA-256"}},n,(new TextEncoder).encode(t));return btoa(String.fromCharCode(...new Uint8Array(a)))}catch(t){throw console.error("Failed to sign data:",t),new Error(`Failed to sign data: ${t}`)}}async function K(t,r,e){try{const n=Uint8Array.from(atob(e),(t=>t.charCodeAt(0))),a=await crypto.subtle.importKey("spki",n,{name:"ECDSA",namedCurve:"P-256"},!1,["verify"]),o=Uint8Array.from(atob(r),(t=>t.charCodeAt(0)));return await crypto.subtle.verify({name:"ECDSA",hash:{name:"SHA-256"}},a,o,(new TextEncoder).encode(t))}catch(t){throw console.error("Failed to verify signature:",t),new Error(`Failed to verify signature: ${t}`)}}export{S as base64Decode,h as base64Encode,o as decryptAES,i as decryptAsyncAES,f as decryptAsyncRSA,m as decryptRSA,n as encryptAES,a as encryptAsyncAES,C as encryptAsyncRSA,b as encryptRSA,r as exportAESKey,t as generateAESKey,g as generateECDSAKeyPair,s as generateHMACKey,p as generateRSAKeyPair,l as generateRandomString,E as getPublicECDSAKey,c as hashSHA256,y as hashSHA512,u as hmacSHA256,w as hmacSHA512,e as importAESKey,d as importRSAPrivateKey,A as importRSAPublicKey,U as signDataECDSA,K as verifySignatureECDSA};
//# sourceMappingURL=index.es.js.map
