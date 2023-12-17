// Forge-node lib
import * as forge from 'node-forge';
//import v8 from 'node:v8'
const { memoryUsage } = require('node:process');
export type rsa_keys = {
    pub_key: string,
    priv_key: string
}
export type encFileAndencPass = {

    file: Buffer,
    loginAndencPass: loginAndencPass[]
}
export type loginAndencPass = {
    login: string,
    pass: string
}
export type encFileAndPass = {
    file: Buffer,
    pass: string
}
export type inputToEncoding = {
    pub_key: string,
    login: string
}

export type hashData = {
    first_part: string,
    second_part: string,
    key: string
}
export type remakedHash = {
    first_part: string,
    second_part: string
}

const keypass_gen_256bit = (): string => {

    const randomBytes = forge.random.getBytesSync(22);
    return forge.util.encode64(randomBytes);

}


const encrypt_data = (data: Buffer, key: string): Buffer => {

    const peace: number = 20480;
    const initializationVector = forge.random.getBytesSync(16);
    const iter = Math.floor(data.length / peace) + 1;
    let encFulePieace: Buffer[] = [];

    const cipher = forge.cipher.createCipher('AES-CTR', forge.util.createBuffer(key));
    cipher.start({ iv: initializationVector });
    
   

    for (let i = 0; i < iter; i++) {

        if (i == 0) {
            cipher.update(forge.util.createBuffer(data.slice(0, peace).toString('binary')))

        }
        else if (i == (iter - 1)) {
            cipher.update(forge.util.createBuffer(data.slice(peace * i).toString('binary')))
        }
        else {
            cipher.update(forge.util.createBuffer(data.slice(peace * i, peace * (i + 1)).toString('binary')));
        }

        encFulePieace.push(Buffer.from(cipher.output.getBytes(), 'binary'))

    }

    cipher.finish();
   
    return Buffer.concat([Buffer.from(initializationVector, 'binary'), Buffer.concat(encFulePieace)]);
};

const decrypt_data = (encryptedData: Buffer, dec_passkey: string): Buffer => {
    const peace: number = 10240;
    const initializationVector = encryptedData.slice(0, 16);
    const iter = Math.floor(encryptedData.length / peace) + 1;
    let encFulePieace: Buffer[] = []
    encryptedData = encryptedData.slice(16);

    const decipher = forge.cipher.createDecipher('AES-CTR', forge.util.createBuffer(dec_passkey));
    decipher.start({ iv: forge.util.createBuffer(initializationVector.toString('binary')) });

    for (let i = 0; i < iter; i++) {

        if (i == 0) {
            decipher.update(forge.util.createBuffer(encryptedData.slice(0, peace).toString('binary')))

        }
        else if (i == (iter - 1)) {
            decipher.update(forge.util.createBuffer(encryptedData.slice(peace * i).toString('binary')))
        }
        else {
            decipher.update(forge.util.createBuffer(encryptedData.slice(peace * i, peace * (i + 1)).toString('binary')));
        }

        encFulePieace.push(Buffer.from(decipher.output.getBytes(), 'binary'))

    }

    decipher.finish();

    return Buffer.concat(encFulePieace);

};


//1. Input: User password
//  Output: rsa pair keys
export const keygen = (password: string): rsa_keys | 'error' => {

    try {

        const keypair: forge.pki.rsa.KeyPair = forge.pki.rsa.generateKeyPair(2048);

        const encryptedPrivateKey = forge.pki.encryptRsaPrivateKey(keypair.privateKey, password);

        const publicKeyPem = forge.pki.publicKeyToPem(keypair.publicKey);

        return { pub_key: publicKeyPem, priv_key: encryptedPrivateKey }

    } catch (error) {
        console.log(error)
        return "error"
    }

}

//2. Input: Data, Public rsa keys
//  Output:  Encrypted data and massive with:  Encrypted passphrase and login
export const data_stream_encryption = (stream: Buffer, pub_key_login: inputToEncoding[]): encFileAndencPass | 'error' => {


    const encrypt_keypass = (pub_key: string, privkey: string): string => {

        let pubk = forge.pki.publicKeyFromPem(pub_key);
        let encrypted = pubk.encrypt(privkey, 'RSA-OAEP');

        return Buffer.from(encrypted, 'binary').toString('base64');

    }

    try {

        let pass_storage: loginAndencPass[] = []
        const key = keypass_gen_256bit()
        //console.time("Измерение Encrytion process");
        let enc_data: Buffer = encrypt_data(stream, key)
        //console.timeEnd("Измерение Encrytion process");
        console.log("Encrfile size: " + enc_data.length)
        //v8.writeHeapSnapshot()

        pub_key_login.forEach((el) => {

            console.log(el.login)

        })

        pub_key_login.forEach((pubkl) => {


            const enckey = encrypt_keypass(pubkl.pub_key, key);

            pass_storage.push({
                pass: enckey,
                login: pubkl.login
            })

        })

        return { file: enc_data, loginAndencPass: pass_storage };

    } catch (error) {
        console.log(error)
        return "error"
    }
}
//3. Input: Encrypted private rsa key, user password; 
//  Output: Private rsa key
export const private_key_decryption = (enc_priv_key: string, passphrase: string): forge.pki.rsa.PrivateKey => {

    return forge.pki.decryptRsaPrivateKey(enc_priv_key, passphrase)

}

//4.  Input: Encrypted data, Encrypted passphrase for this data, private rsa key, user password; 
//   Output: Data
export const data_stream_decryption = (encryptedData: Buffer, enc_passkey: string, enc_priv_key: string, passphrase: string): Buffer | 'error' => {

    const decrypt_keypass = (priv_key: forge.pki.rsa.PrivateKey, enc_key: string): string => {

        let decrkey = priv_key.decrypt(Buffer.from(enc_key, 'base64').toString('binary'), 'RSA-OAEP');
        return decrkey

    }
    try {
        //Расшифровываем encrypted private rsa key
        const dec_privkey: forge.pki.rsa.PrivateKey = private_key_decryption(enc_priv_key, passphrase);

        //Расшифровываем encrypted passphrase for data
        const dec_passkey: string = decrypt_keypass(dec_privkey, enc_passkey);
        //console.time("Измерение Decrytion process");
       // console.timeEnd("Измерение Decrytion process");
        return decrypt_data(encryptedData, dec_passkey)

    } catch (error) {
        console.log(error)
        return "error";
    }
}


// 5. Шифрование общедоступных файлов
export const data_stream_encryption_public = (data: Buffer): encFileAndPass | 'error' => {

    try {
        let key256bit = keypass_gen_256bit()
        return { file: encrypt_data(data, key256bit), pass: key256bit }
    } catch (error) {
        console.log(error)
        return 'error'
    }
}
// 6. Расшифрование общедоступных файлов
export const data_stream_decryption_public = (data: Buffer, key: string): Buffer | 'error' => {
    try {
        return decrypt_data(data, key)
    } catch (error) {
        console.log(error)
        return 'error'
    }
}

// 7. Генерация хэша
export const hashmake = (login: string, password: string): hashData | 'error' => {
    try {

        let key: string = keypass_gen_256bit()

        let hash: string = forge.md.sha256.create().update(key).update(password.concat("&" + login)).digest().toHex()

        let hash_len = hash.length;
        console.log(hash.substring(0, hash_len / 2).length)
        console.log(hash.substring( hash_len / 2, hash_len).length)
        console.log(key.length)
        return {
            first_part: hash.substring(0, hash_len / 2),
            second_part: hash.substring(hash_len / 2, hash_len),
            key: key
        }

    } catch (error) {
        console.log(error)
        return 'error'
    }
}

// 8. Воссоздание хэша
export const hashRemake = (key: string, login: string, password: string): remakedHash | 'error' => {
    try {

        let hash: string = forge.md.sha256.create().update(key).update(password.concat("&" + login)).digest().toHex()

        let hash_len = hash.length;

        return {
            first_part: hash.substring(0, hash_len / 2),
            second_part: hash.substring(hash_len / 2, hash_len),

        }

    } catch (error) {
        console.log(error)
        return 'error'
    }
}
