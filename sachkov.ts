import * as fs from 'fs';
import exec from 'await-exec-typescript'



async function cmd(text: string) {
    let out = ''
    await exec(text).then((res) => {
        out = res.stdout
    })
    return out
}



export const main = async () => {

    const filebuf: string[] = fs.readdirSync("./sach/BBSO_01_20/1_fd06aa8c",)
    console.log("All: " + filebuf.length)

    let chunks: string[] = [];
    let target: string = '';
    filebuf.forEach((file) => {
        if (file.substring(file.length - 4, file.length) == "file") { 
            return 
        }
        else if (file.substring(file.length - 3, file.length) == "sig") {
            chunks.push(file)
        } else if (file.substring(file.length - 3, file.length) == "gpg") {
            target = file
        }

    });
    chunks.forEach(chunk => {
        filebuf.splice(filebuf.indexOf(chunk), 1)
    });
    filebuf.splice(filebuf.indexOf(target), 1);
    console.log(".files: " + filebuf.length);

    await cmd('gpg --import ./sach/pub_bbso_23.key');
    
   
}
main()