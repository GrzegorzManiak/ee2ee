export class EE2EE {
    #crypto:any;
    #client:any;

    sharedPrivateKey:any;
    sharedPublicKey:any;
    bPublicKey:any = undefined;

    constructor(crypto:any, sPublicKey?:any, bPublicKey?:any) {
        this.#crypto = crypto;

        if(sPublicKey) this.sharedPublicKey = sPublicKey;
        else this.sharedPublicKey = crypto.createDiffieHellman(256).getPrime();

        this.#client = crypto.createDiffieHellman(this.sharedPublicKey);
        this.#client.generateKeys();

        if(bPublicKey) {
            this.bPublicKey = bPublicKey;
            this.sharedPrivateKey = this.#client.computeSecret(bPublicKey);
        }
    }

    getPublicKey() {
        return this.#client.getPublicKey();
    }

    getSharedPrivateKey() {
        if(!this.bPublicKey)
            throw new Error("bPub key is not defined");

        this.sharedPrivateKey = this.#client.computeSecret(this.bPublicKey);
        return this.sharedPrivateKey;
    }

    #byteArrayToBase64(byteArray:any) {
        return Buffer.from(byteArray).toString('base64');
    }
    
    #base64ToByteArray(base64:string) {
        return Buffer.from(base64, 'base64');
    }

    encrypt(data:string):any {
        let iv:any = this.#crypto.randomBytes(64),
            cipher:any = this.#crypto.createCipheriv('aes-256-gcm', this.sharedPrivateKey, iv),
            encrypted:string = cipher.update(data, 'utf8', 'hex');
    
        encrypted += cipher.final('hex');
    
        let tag64:string = this.#byteArrayToBase64(cipher.getAuthTag()),
            iv64:string= this.#byteArrayToBase64(iv);
    
        return {
            content: encrypted,
            tag: tag64,
            iv: iv64,
            complete: `${encrypted}.${tag64}.${iv64}`
        };
    }

    decryptCompact(data:string):string {
        let [content, tag, iv]:any = data.split('.');
        return this.decrypt(content, tag, iv);
    }

    decrypt(content:any, tag:any, iv:any):string {
        tag = this.#base64ToByteArray(tag);
        iv = this.#base64ToByteArray(iv);
    
        let decipher:any = this.#crypto.createDecipheriv('aes-256-gcm', this.sharedPrivateKey, iv);
        decipher.setAuthTag(tag);
    
        let decrypted:any = decipher.update(content, 'hex', 'utf8');
        decrypted += decipher.final('utf8');
    
        return decrypted;
    }
}