import { data_stream_decryption, data_stream_decryption_public, data_stream_encryption, data_stream_encryption_public, encFileAndencPass, inputToEncoding, keygen, rsa_keys } from "./crypto_work";
import * as fs from 'fs';


const test_key_generation = ()=> {

    let user_password = "qwerty"
    ////
    let new_user_rs_keys: rsa_keys | 'error' = keygen(user_password);

    if (new_user_rs_keys == 'error') { 
        console.log("keygen error")
        return;
    } 
    ////
    console.log("Private rsa key: \n"+new_user_rs_keys.priv_key+"Public rsa key: \n"+new_user_rs_keys.pub_key);
  

}

const test_data_stream_encryption= ()=> {
    // gen key for this test
    let user_password1 = "qwerty"
    let user_password2 = "dambelbas"
    ///
    let new_user1_rs_keys: rsa_keys | 'error' = keygen(user_password1);
    let new_user2_rs_keys: rsa_keys | 'error' = keygen(user_password2);

    if (new_user1_rs_keys == 'error') { 
        console.log("keygen error")
        return;
    } 
    if (new_user2_rs_keys == 'error') { 
        console.log("keygen error")
        return;
    } 
    ////
    
    let inputKeyAndPss: inputToEncoding[] = [{
        pub_key:new_user1_rs_keys.pub_key,
        login: "user1"

    },{
        pub_key:new_user1_rs_keys.pub_key,
        login: "user2"

    },]
    

    const filebuf: Buffer = fs.readFileSync("./Simpletext.pdf")
    ////
    let encrypted_info: "error" | encFileAndencPass[] = data_stream_encryption(filebuf,inputKeyAndPss)
    if (encrypted_info == 'error') { 
        console.log("keygen error")
        return;
    } 
    ////
    encrypted_info.forEach(element =>{
        console.log("Info after encripting for "+element.login)
        console.log("\nEncrypted passphrase: \n"+element.pass)
        console.log("\nEncrypted file: \n"+element.file.toString().substring(0,100))

    })
}


const test_full_function= ()=> {
    // gen key for this test
    let user_password1 = "qwerty"
    let user_password2 = "dambelbas"
    ////
    let new_user1_rs_keys: rsa_keys | 'error' = keygen(user_password1);
    let new_user2_rs_keys: rsa_keys | 'error' = keygen(user_password2);
    if (new_user1_rs_keys == 'error') {
        console.log("keygen error")
        return;
    } 
    if (new_user2_rs_keys == 'error') { 
        console.log("keygen error")
        return;
    } 
    ////
    
    let inputKeyAndPss: inputToEncoding[] = [{
        pub_key:new_user1_rs_keys.pub_key,
        login: "user1"

    },{
        pub_key:new_user2_rs_keys.pub_key,
        login: "user2"

    },]
    

    const filebuf: Buffer = fs.readFileSync("./Simpletext.pdf")
    console.log("\nFile:\n"+filebuf.toString().substring(0,100)+"\n")
    
    ////
    let encrypted_info: "error" | encFileAndencPass[] = data_stream_encryption(filebuf,inputKeyAndPss)
    if (encrypted_info == 'error') { 
        console.log("keygen error")
        return;
    } 
    ///

    encrypted_info.forEach(element =>{
        console.log("Info after encripting for "+element.login)
        console.log("\nEncrypted passphrase: \n"+element.pass)
        console.log("\nEncrypted file: \n"+element.file.toString().substring(0,100))

    })

    ////
    let decr_data: Buffer | 'error'=  data_stream_decryption(encrypted_info[0].file,encrypted_info[0].pass,new_user1_rs_keys.priv_key,user_password1);
    let decr_data2: Buffer | 'error'=  data_stream_decryption(encrypted_info[1].file,encrypted_info[1].pass,new_user2_rs_keys.priv_key,user_password2);
    ////
    console.log("Decoded with user1 keys:\n"+decr_data.toString().substring(0,100))
    console.log("\nDecoded with user2 keys:\n"+decr_data2.toString().substring(0,100))
    
}

const test_public_crypt = () => {
    const filebuf: Buffer = fs.readFileSync("./pngegg.png")
    let a = data_stream_encryption_public(filebuf)
    if(a != 'error'){
        let r =data_stream_decryption_public(a.file,a.pass)
        fs.writeFileSync("./output/testenc",a.file)
        if (r != 'error'){
            fs.writeFileSync("./output/test",r,)
        }

    }

}

//test_full_function()
test_public_crypt()