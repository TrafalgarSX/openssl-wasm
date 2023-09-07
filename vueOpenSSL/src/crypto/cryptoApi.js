export function generateKeyPair()

export function sign(data, privateKey, { der, publicKey, userId, hash} = {});

export function verify(data, publicKey, signature, {der, hash, userId} = {});

// cipherMode 1-C1C3C2, 2-C1C2C3 
export function encrypt(data, publicKey, cipherMode);

export function decrypt(encrypted, privateKey, cipherMode, {output = 'string'} = {});

export function sm4Encrypt(key, data, {padding = 'pkcs#7', mode, iv = [], output = 'string'} = {});

export function sm4Decrypt(key, data, {padding = 'pkcs#7', mode, iv = [], output = 'string'} = {});

export function sm4GcmEncrypt(plaintext, key, iv, { aad = '', output = 'string' } = {}); 
export function sm4GcmDecrypt(ciphertext, key, iv, tag, { aad = '', output = 'string' } = {});


export function pbkdf2(password, salt, iterations, keyLength, hashAlgorithm);

options = {
    inputEncoding: 'string',
    outputEncoding: 'string'
};

// data 编码如何规定？  基本 hex  array
export function digest(data, options);

export function hamc(key, data, options);

