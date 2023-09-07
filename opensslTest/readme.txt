该文件夹是对 openssl 一些算法的简单封装，方便使用
1. sm2 encrypt  decrypt sign verify, genkeypair 
2. symm encrypt decrypt
3. hmac 
4. hash
5. 包含了一些工具函数, 可以实现从sm2私钥中 extract sm2公钥,
   从 uint8_t 数组中转换 Openssl 的公私钥结构体
