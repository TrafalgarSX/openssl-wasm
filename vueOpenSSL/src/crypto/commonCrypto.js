import CryptoJS from 'crypto-js';

export function EncryptAESCBC(key, iv, data){
     // 统一将传入的字符串转成UTF8编码
    const dataHex = CryptoJS.enc.Hex.parse(data) // 需要加密的数据
    const keyHex = CryptoJS.enc.Hex.parse( key ) // 秘钥
    const ivHex = CryptoJS.enc.Hex.parse( iv ) // 偏移量
    const encrypted = CryptoJS.AES.encrypt( dataHex , keyHex , {
      iv: ivHex,
      mode: CryptoJS.mode.CBC, // 加密模式
      padding: CryptoJS.pad.Pkcs7
    })
    let encryptedVal = encrypted.ciphertext.toString()
    return encryptedVal //  返回加密后的值
}