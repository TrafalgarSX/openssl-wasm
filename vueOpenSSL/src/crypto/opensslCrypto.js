import Module from './openssl_func.js'
import {hexToUint8Array, uint8ArrayToHex, stringToUint8Array} from '../utils/hexUtil'

const wasmInstance = await Module

const mallocByteBuffer = len => {
    const ptr = wasmInstance._malloc(len)
    const heapBytes = new Uint8Array(wasmInstance.HEAPU8.buffer, ptr, len)
    return heapBytes
}

const mallocInt32Buffer = len => {
    const ptr = wasmInstance._malloc(len)
    const heapUInt32 = new Uint32Array(wasmInstance.HEAPU32.buffer, ptr, len)
    return heapUInt32
}

export function WasmSm2EncDec(inPutHexText, keyBytes, enc){
    const sm2_encrypt_decrypt = wasmInstance.cwrap('sm2_encrypt_decrypt', 'number', ['array', 'number', 'array', 'number', 'number', 'number', 'number']);

    // msgHexText  to unint8Array
    const inputBytes = hexToUint8Array(inPutHexText);
    const resultLen = mallocInt32Buffer(1);
    const resultAddress = mallocInt32Buffer(1);

    // 调用openssl_hmac函数
    const result = sm2_encrypt_decrypt(inputBytes, inputBytes.byteLength, keyBytes, keyBytes.byteLength, resultAddress.byteOffset, resultLen.byteOffset, enc);

    const outBuffer = new Uint8Array(wasmInstance.HEAPU8.buffer, resultAddress[0], resultLen[0]);

    console.log(`type  sm2 enc or dec ${enc} result is: ${uint8ArrayToHex(outBuffer)}`);
    console.log(`type  sm2 enc or dec ${enc} resultLen is : ${resultLen[0]}`);
    console.log(`type  sm2 enc or dec ${enc} excute result is: ${result}`);

    let outBufferHex = uint8ArrayToHex(outBuffer);
    wasmInstance._free(outBuffer);
    wasmInstance._free(resultLen);
    wasmInstance._free(resultAddress);
    return outBufferHex;
}

export function WasmSymmEncDec(type, keyBytes, ivBytes, inPutHexText, outLen, enc){
    // 后续改动
    const symm_encrypt_decrypt = wasmInstance.cwrap('symm_encrypt_decrypt', 'number', ['number', 'array', 'array', 'array', 'number', 'number', 'number']);

    // msgHexText  to unint8Array
    const inputBytes = hexToUint8Array(inPutHexText);
    const outBuffer = mallocByteBuffer(outLen)
    const resultLen = mallocInt32Buffer(1);

    // 调用openssl_hmac函数
    const result = symm_encrypt_decrypt(type, keyBytes, ivBytes, inputBytes, inputBytes.byteLength, outBuffer.byteOffset, resultLen.byteOffset, enc);
    // 后续改动
    // const result = symm_encrypt_decrypt(type, keyBytes, ivBytes, inputBytes, inputBytes.byteLength, outBuffer.byteOffset, resultLen.byteOffset, enc);
    console.log(`type ${type} symm enc or dec ${enc} result is: ${uint8ArrayToHex(outBuffer)}`);
    console.log(`type ${type} symm enc or dec ${enc} resultLen is : ${resultLen[0]}`);
    console.log(`type ${type} symm enc or dec ${enc} excute result is: ${result}`);

    wasmInstance._free(outBuffer);
    wasmInstance._free(resultLen)
    return uint8ArrayToHex(outBuffer)
}

export function WasmSymmCBCEncDec(type, keyBytes, ivBytes, inPutHexText, outLen, enc){
    const symm_cbc_encrypt_decrypt = wasmInstance.cwrap('symm_encrypt_decrypt', 'number', ['number', 'array', 'array', 'array', 'number', 'number', 'number']);

    // msgHexText  to unint8Array
    const inputBytes = hexToUint8Array(inPutHexText);
    const outBuffer = mallocByteBuffer(outLen)
    const resultLen = mallocInt32Buffer(1);

    const result = symm_cbc_encrypt_decrypt(type, keyBytes, ivBytes, inputBytes, inputBytes.byteLength, outBuffer.byteOffset, resultLen.byteOffset, enc);
    console.log(`type ${type} symm enc or dec ${enc} result is: ${uint8ArrayToHex(outBuffer)}`);
    console.log(`type ${type} symm enc or dec ${enc} resultLen is : ${resultLen[0]}`);
    console.log(`type ${type} symm enc or dec ${enc} excute result is: ${result}`);

    wasmInstance._free(outBuffer);
    wasmInstance._free(resultLen)
    return uint8ArrayToHex(outBuffer)
}

export function WasmHmac(type, msgText, keyBytes, outLen){
    const openssl_hmac = wasmInstance.cwrap('openssl_hmac', 'number', ['number', 'array', 'number', 'array', 'number', 'number', 'number']);

    const key_len = keyBytes.length;
    // msgText  to unint8Array
    const msgBytes = stringToUint8Array(msgText);
    const outBuffer = mallocByteBuffer(outLen)
    const hmacLen = mallocInt32Buffer(1);

    // 调用openssl_hmac函数
    const result = openssl_hmac(type, keyBytes, key_len, msgBytes, msgBytes.byteLength, outBuffer.byteOffset, hmacLen.byteOffset);
    console.log(`type ${type} hmac result is: ${uint8ArrayToHex(outBuffer)}`);
    console.log(`type ${type} hmacLen value is: ${hmacLen[0]}`);
    console.log(`type ${type} hmac excute result is: ${result}`);

    wasmInstance._free(outBuffer);
    wasmInstance._free(hmacLen)
}

export function WasmHash(type, msgText, outLen){
    const openssl_hash = wasmInstance.cwrap('openssl_hash', 'number', ['number', 'array', 'number', 'number', 'number']);

    // msgText  to unint8Array
    const msgBytes = stringToUint8Array(msgText);
    const outBuffer = mallocByteBuffer(outLen)
    const heapUInt32 = new Uint32Array(1)
    // const hashLen = mallocInt32Buffer(1);

    // 调用openssl_hash函数
    const result = openssl_hash(type, msgBytes, msgBytes.byteLength, outBuffer.byteOffset, heapUInt32);
    // console.log(`type ${type} hash result is: ${uint8ArrayToHex(outBuffer)}`);
    // console.log(`type ${type} hashLen value is: ${hashLen[0]}`);
    // console.log(`type ${type} hash excute result is: ${result}`);

    wasmInstance._free(outBuffer);
    // wasmInstance._free(hashLen)
    return uint8ArrayToHex(outBuffer)
}

export async function test(){
    console.log("test wasm function")

    // hmac test
    let hmacKey = hexToUint8Array("CCA785EAF8F1CD24ECEA8FCF6717F13C8290A2E83BCA75605BAF2EA8102E8EECECD0CF5B435AE4B844B3611333AECDF2BB096DC48CB182348A5F7B4BEA76BD03");
    WasmHmac(7, "Hello, World!", hmacKey, 32) // sm3
    WasmHmac(1, "Hello, World!", hmacKey, 16) // md5
    WasmHmac(2, "Hello, World!", hmacKey, 20) // sha1
    WasmHmac(4, "Hello, World!", hmacKey, 32) // sha256
    WasmHmac(6, "Hello, World!", hmacKey, 64) // sha512
    WasmHmac(5, "Hello, World!", hmacKey, 48) // sha384
    WasmHmac(3, "Hello, World!", hmacKey, 28) // sha224

    // hash test
    WasmHash(7, "Hello, World!", 32) // sm3
    WasmHash(1, "Hello, World!", 16) // md5
    WasmHash(2, "Hello, World!", 20) // sha1
    WasmHash(4, "Hello, World!", 32) // sha256
    WasmHash(6, "Hello, World!", 64) // sha512
    WasmHash(5, "Hello, World!", 48) // sha384
    WasmHash(3, "Hello, World!", 28) // sha224

    // sm4 symm ecb encrypt decrypt
    let sm4key = hexToUint8Array('4E9D6BA20F45ECBCF3C884C627115A40') // 密钥为16进制字符串
    let sm4iv = hexToUint8Array('4E9D6BA20F45ECBCF3C884C627115A40' ) // iv为16进制字符串
    let encrypted = WasmSymmEncDec(1, sm4key, sm4iv, "48656C6C6F2C20576F726C6421", 16, 1) // sm4 ecb encrypt
    let decrypted = WasmSymmEncDec(1, sm4key, sm4iv, encrypted, 16, 0) // sm4 ecb encrypt
    // sm4 symm cbc encrypt decrypt
    let cbcEncrypted = WasmSymmCBCEncDec(2, sm4key, sm4iv, "48656C6C6F2C20576F726C6421", 16, 1) // sm4 cbc encrypt
    let cbcDecrypted = WasmSymmCBCEncDec(2, sm4key, sm4iv, cbcEncrypted, 16, 0) // sm4 cbc encrypt

    // sm2 encrypt decrypt
    let sm2_public_key = hexToUint8Array("04A1AADB44CA2F159A594E49BF60DEC307285F768C872C1395FC4791E2064F1290F1C1A1C5E58FFD9DDC93BD54226167CA4F93738EC3395F0DFFF8E275EE355A4A");
    let sm2_private_key = hexToUint8Array("52CC193E65308285421D8BA7F583722647C7A2D3FD36B1B177A009EC0824FAF1");
    let sm2_encrypted = WasmSm2EncDec("48656C6C6F2C20576F726C6421", sm2_public_key, 1);

    let encrypted_hex = "801ee34cec572baca2d85f5b9d16b2070856685e3af513c6c3e6b806979fb4090cb65b34dcd3ea8cbb41f19eb7df852ca539d001dceb6499fe76904bccc17c6ee8d9f7eba739c8f239e1cdf9cb8b7c6d8a8f0a0f6569403d4463346bd91e48b259e0ab58cb3c25db9ea6ef32d0";
    let sm2_decrypted_hex = WasmSm2EncDec(encrypted_hex, sm2_private_key, 0);
    let sm2_decrypted = WasmSm2EncDec(sm2_encrypted, sm2_private_key, 0);
}


export async function testTime(){
    // let hmacKey = hexToUint8Array("CCA785EAF8F1CD24ECEA8FCF6717F13C8290A2E83BCA75605BAF2EA8102E8EECECD0CF5B435AE4B844B3611333AECDF2BB096DC48CB182348A5F7B4BEA76BD03");
    console.time('testTime');
    for (let index = 0; index < 100; index++) {
    //   let result = await WasmHash(7, 'Hello, World!', 32); // sm3
      let result = await WasmHash(7, 'Hello, World!', 32); // sm3
      console.log(result);
    //   await WasmHmac(7, 'Hello, World!', hmacKey, 32) // sm3
    }
    console.timeEnd('testTime');
}