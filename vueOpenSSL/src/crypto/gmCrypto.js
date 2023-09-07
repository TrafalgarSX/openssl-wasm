// const CryptoJS = require('sm-crypto')
import CryptoJS from 'sm-crypto'
import {SM2, SM3, SM4} from 'gm-crypto'
// import * as CryptoJS from 'sm-crypto'
import {stringToHex} from '../utils/hexUtil'

export function smCryptoTest(){
  console.log(SM3.digest('hello', 'utf8', 'hex')); 
  console.log(SM3.digest('68656C6C6F', 'hex', 'hex')); 

  // CryptoJS.sm2 enc dec
  let keypair = CryptoJS.sm2.generateKeyPairHex()
  // const {privateKey, publicKey} = keypair

  let publicKey = keypair.publicKey // 公钥
  let privateKey = keypair.privateKey // 私钥

  // output publicKey and privateKey
  console.log('publicKey is :' + publicKey);
  console.log('privateKey is :' + privateKey);

  const mode = {
    C1C3C2: 1,
    C1C2C3: 0
  }

  let msgString = 'message' // 明文字符串
  let msgHex = stringToHex(msgString) // 明文字符串转16进制
  let msgArray = [1, 2, 3, 4, 5] // 明文数组

  console.log('msgHex is :' + msgHex);

  let encryptData = CryptoJS.sm2.doEncrypt(msgString, publicKey, mode.C1C3C2, {output: 'hex'}) // 加密结果
  console.log('encryptData is :' + encryptData);
  let decryptData = CryptoJS.sm2.doDecrypt(encryptData, privateKey, mode.C1C3C2, {hexstring: true}) // 解密结果
  console.log('decryptData is :' + decryptData);

  encryptData = CryptoJS.sm2.doEncrypt(msgArray, publicKey, mode.C1C3C2) // 加密结果，输入数组
  console.log('encryptData is :' + encryptData);
  decryptData = CryptoJS.sm2.doDecrypt(encryptData, privateKey, mode.C1C3C2, {output: 'array'}) // 解密结果，输出数组
  console.log('decryptData is :' + decryptData);

  // CryptoJS.sm2 sign and verify
  let signValueHex = CryptoJS.sm2.doSignature(msgString, privateKey) // 签名
  console.log('sigValueHex is :' + signValueHex);
  let verifyResult = CryptoJS.sm2.doVerifySignature(msgString, signValueHex, publicKey) // 验签结果
  console.log('verifyResult is :' + verifyResult);

  signValueHex = CryptoJS.sm2.doSignature(msgString, privateKey, {hash: true, publicKey, der: true}) // 签名
  console.log('der sigValueHex is :' + signValueHex);
  verifyResult = CryptoJS.sm2.doVerifySignature(msgString, signValueHex, publicKey, {hash: true, publicKey, der: true}) // 验签结果
  console.log('der verifyResult is :' + verifyResult);

  // CryptoJS.sm4 encrypt and decrypt
  // let keyHex = CryptoJS.sm4.generateKey() // 生成密钥
  // console.log('keyHex is :' + keyHex);
  let keyHex = '0123456789abcdeffedcba9876543210' // 密钥为16进制字符串
  let symmEncryptData = CryptoJS.sm4.encrypt(msgHex, keyHex, {hexstring: true}) // 加密结果
  console.log('CryptoJS.sm4 encryptData is :' + symmEncryptData);
  let symmDecryptData = CryptoJS.sm4.decrypt(symmEncryptData, keyHex, {hexstring: true}) // 解密结果
  console.log('CryptoJS.sm4 decryptData is :' + symmDecryptData);

  // CryptoJS.sm4 cbc encrypt and decrypt
  let ivHex = 'fedcba98765432100123456789abcdef' // 生成iv
  let symmEncryptDataCbc = CryptoJS.sm4.encrypt(msgHex, keyHex, {hexstring: true, mode: 'cbc', iv: ivHex}) // 加密结果
  console.log('CryptoJS.sm4 cbc encryptData is :' + symmEncryptDataCbc);
  let symmDecryptDataCbc = CryptoJS.sm4.decrypt(symmEncryptDataCbc, keyHex, {hexstring: true, mode: 'cbc', iv: ivHex}) // 解密结果
  console.log('CryptoJS.sm4 cbc decryptData is :' + symmDecryptDataCbc);

  // CryptoJS.sm3 hash
  // let hashData = CryptoJS.sm3(msgHex, {hexstring: true}) // hash结果
  let hashData = CryptoJS.sm3(msgString) // hash结果
  console.log('hashData is :' + hashData);
  // hmac CryptoJS.sm3
  let hmacData = CryptoJS.sm3(msgString, {
           hexstring: true, 
           key: 'daac25c1512fe50f79b0e4526b93f5c0e1460cef40b6dd44af13caec62e8c60e0d885f3c6d6fb51e530889e6fd4ac743a6d332e68a0f2a3923f42585dceb93e9'
           }) // hmac结果
  console.log('hmacData is :' + hmacData);
}


export function gmCryptoTestTime(){
    // caculte consume time

    console.time("gmCryptoTestTime");
    for (let index = 0; index < 100; index++) {
        let result = SM3.digest('Hello, World!', 'utf8', 'hex')
        console.log(result);
    }
    console.timeEnd("gmCryptoTestTime");
}