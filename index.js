'use strict';

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

class FileCrypto {
  constructor(key = '', iv = '') {
    this.algorithm = 'aes-256-cbc';
    this.key = Buffer.alloc(32, '0');
    this.iv = Buffer.alloc(16, '0');

    let keys = key !== undefined && key !== null && typeof key === 'string' ? [...key.trim()] : []
    for (let i = 0; i < this.key.length; i++) {
      if (keys.length > i) {
        this.key.write(keys[i], i, 1);
      }
    }

    let ivs = iv !== undefined && iv !== null && typeof iv === 'string' ? [...iv.trim()] : []
    for (let i = 0; i < this.iv.length; i++) {
      if (ivs.length > i) {
        this.iv.write(ivs[i], i, 1);
      }
    }
  }

  encrypt(str) {
    let crypted;
    try {
      if (typeof str !== 'string') {
        throw new Error(`invalid type[${typeof str}]`);
      }
      const cipher = crypto.createCipheriv(this.algorithm, this.key, this.iv);
      const buf1 = cipher.update(str, 'hex');
      const buf2 = cipher.final();
      crypted = Buffer.concat([buf1, buf2], buf1.length + buf2.length)
    } catch (error) {
      console.error(error);
      crypted = null;
    }
    return crypted;
  }

  decrypt(str) {
    let decrypted;
    try {
      if (typeof str !== 'string') {
        throw new Error(`invalid type[${typeof str}]`);
      }
      const decipher = crypto.createDecipheriv(this.algorithm, this.key, this.iv);
      const buf1 = decipher.update(str, 'hex');
      const buf2 = decipher.final();
      decrypted = Buffer.concat([buf1, buf2], buf1.length + buf2.length)
    } catch (error) {
      console.error(error);
      decrypted = null;
    }
    return decrypted;
  }
}

try {

  if (process.argv.length !== 6) {
    throw new Error('invalid parameter length, expect [6]')
  }

  if (process.argv[2] !== '-e' && process.argv[2] !== '-d') {
    throw new Error('invalid parameter(3), expect [-e|-d]')
  }

  const file = path.resolve(process.argv[5]);
  if (!fs.existsSync(file)) {
    throw new Error(`invalid parameter(6), file(${file}) not exist`);
  }

  const fileCrypto = new FileCrypto(process.argv[3], process.argv[4]);

  console.table([{
    '模式': process.argv[2] === '-e' ? '加密' : '解密',
    '密钥key': fileCrypto.key.toString(),
    '向量iv': fileCrypto.iv.toString(),
    '文件路径': file,
  }]);

  switch (process.argv[2]) {
    case '-e':
      fs.writeFileSync(path.join(__dirname,'tmp','encrypted_file'), fileCrypto.encrypt(fs.readFileSync(file).toString('hex')));
      break;
    case '-d':
      fs.writeFileSync(path.join(__dirname,'tmp','decrypted_file'), fileCrypto.decrypt(fs.readFileSync(file).toString('hex')));
      break;
  }

  console.log('success!!!');
} catch (error) {
  console.error('failed!!!', error);
}
