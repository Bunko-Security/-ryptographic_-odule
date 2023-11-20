import crypto, { KeyObject } from 'crypto';

export type rsa_keys = {
    pub_key: string,
    priv_key: string
}
export type encFileAndencPass = {
    login: string,
    file: Buffer,
    pass: string
}
export type inputToEncoding = {
    pub_key: string, 
    login: string
}

//1. Input: User password
//  Output: rsa pair keys
export const keygen = (password: string):  rsa_keys | 'error' => {
    
    try{
        const { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', {
            modulusLength: 2048,
            publicKeyEncoding: {
                type: 'spki',
                format: 'pem'
            },
            privateKeyEncoding: {
                cipher:'aes-256-cbc',
                type: 'pkcs8',
                format: 'pem',
                passphrase: password
            }
        }); 
        return {pub_key:publicKey,priv_key:privateKey} as rsa_keys
      
    } catch(error){
        console.log(error)
        return "error"
    }
    
}

//2. Input: Data, Public rsa keys
//  Output: massive with:  Encrypted data, Encrypted passphrase
export const data_stream_encryption = (stream: Buffer, pub_key_login: inputToEncoding[]): encFileAndencPass[] | 'error'=> {

    const encrypt_data =  (data: Buffer , key: string): Buffer => {
        const initializationVector = crypto.randomBytes(16);
        const cipher = crypto.createCipheriv("aes-256-ctr", key, initializationVector);
        
        const encrypted = Buffer.concat([initializationVector, cipher.update(data), cipher.final()]);
    
        return encrypted;
    };
    const keypass_gen_32 = (): string =>{

        const randomBytes = crypto.randomBytes(22);
        return randomBytes.toString('base64');

    }
            
    const encrypt_keypass = (pub_key: string, privkey:string): string => {

        crypto.publicEncrypt(pub_key, Buffer.from(privkey));

        return crypto.publicEncrypt(pub_key, Buffer.from(privkey)).toString('base64');

    }

    try{
        let storage: encFileAndencPass[]=[]
        
        pub_key_login.forEach((pubkl)=>{

            const key = keypass_gen_32()
            let enc_data = encrypt_data(stream,key)
            const enckey = encrypt_keypass(pubkl.pub_key,key)

            storage.push({
                file: enc_data,
                pass: enckey,
                login: pubkl.login
            })

        })

        return storage;

    } catch(error){
        console.log(error)
        return "error"
    }
}


//3. Input: Encrypted private rsa key, user password; 
//  Output: Private rsa key
export const private_key_decryption =(enc_priv_key: string,passphrase: string): KeyObject => {
    
    return  crypto.createPrivateKey({passphrase:passphrase,key:enc_priv_key,});
   
}

//4.  Input: Encrypted data, Encrypted passphrase for this data, private rsa key, user password; 
//   Output: Data
export const data_stream_decryption = (encryptedData: Buffer, enc_passkey: string, enc_priv_key: string, passphrase: string): Buffer | 'error'=> {

    const decrypt_keypass = (priv_key: KeyObject, enc_key: string): string =>{

        return crypto.privateDecrypt(priv_key,Buffer.from(enc_key,'base64')).toString('utf-8')
                
    }
    try{
        //Расшифровываем encrypted private rsa key
        const dec_privkey: KeyObject = private_key_decryption(enc_priv_key,passphrase);
    
        //Расшифровываем encrypted passphrase for data
        const dec_passkey: string = decrypt_keypass(dec_privkey,enc_passkey);
        
        const initializationVector = encryptedData.slice(0,16);
        encryptedData = encryptedData.slice(16);
        const decipher = crypto.createDecipheriv('aes-256-ctr', dec_passkey, initializationVector);
        return Buffer.concat([decipher.update(encryptedData), decipher.final()]);  

    } catch(error){
        console.log(error)
        return "error";
    }
}


export default{
    keygen,
    data_stream_encryption,
    private_key_decryption,
    data_stream_decryption
}





