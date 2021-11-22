const crypto = require('crypto');

export class EE2EE {
    #client:any;

    sharedPrivateKey:any;
    sharedPublicKey:any;

    aPublicKey:any;
    bPublicKey:any = undefined;

    // self explanatory, converts a byte array to base64 string
    #byteArrayToBase64(byteArray:any) {
        return Buffer.from(byteArray).toString('base64');
    }
    
    // self explanatory, converts base64 string to a byte array
    #base64ToByteArray(base64:string) {
        return Buffer.from(base64, 'base64');
    }

    constructor(sPublicKey?:any, bPublicKey?:any) {
        // If the Shared Key, and the B public key are set.
        // I will assume that this is the client, not the server,
        // in other words, this is Alice, Bob has generated his
        // shared public key and his public key, and Alice is 
        // receiving his keys, therefor the shared private keys are
        // automatically generated.

        // If the sPublicKey isnt set, generate a new shared key
        if(sPublicKey) this.sharedPublicKey = sPublicKey;
        else this.sharedPublicKey = crypto.createDiffieHellman(256).getPrime();

        // establish the client
        this.#client = crypto.createDiffieHellman(this.sharedPublicKey);
        this.#client.generateKeys();
        this.aPublicKey = this.#client.getPublicKey();

        // if the B public key and the S Public key are provided, generate the shared private key
        if(bPublicKey && sPublicKey) {
            this.bPublicKey = bPublicKey;
            this.sharedPrivateKey = this.#client.computeSecret(bPublicKey);
        }
    }


    // Gets the shared private key of user A and user B
    getSharedPrivateKey() {
        // If the b public key isint set, throw an error
        if(!this.bPublicKey) 
            throw new Error("bPub key is not defined");

        // set the shared private key to a class variable
        this.sharedPrivateKey = this.#client.computeSecret(this.bPublicKey);

        // return the shared private key
        return this.sharedPrivateKey;
    }

    // Encrpts the data using the established shared private key
    encrypt(data:string):any {
        let iv:any = crypto.randomBytes(64), // generate a random iv using nodes crypto module
            cipher:any = crypto.createCipheriv('aes-256-gcm', this.sharedPrivateKey, iv), // using aes-256-gcm, the shared private key and the iv, create the cipher
            encrypted:string = cipher.update(data, 'utf8', 'hex'); // encrypt the data
    
        encrypted += cipher.final('hex');
        
        // convert the tag and iv to base64
        let tag64:string = this.#byteArrayToBase64(cipher.getAuthTag()),
            iv64:string= this.#byteArrayToBase64(iv);
        
        return {
            content: encrypted,
            tag: tag64,
            iv: iv64,
        };
    }

    // Decrypts the data if given the correct encrypted data, shared key, tag and iv
    decrypt(content:any, tag:any, iv:any):string {
        // Grab the tag and iv
        tag = this.#base64ToByteArray(tag);
        iv = this.#base64ToByteArray(iv);
        
        // create the decipher using the shared private key, the tag and the iv
        let decipher:any = crypto.createDecipheriv('aes-256-gcm', this.sharedPrivateKey, iv);
        decipher.setAuthTag(tag);
        
        // finaly, decrypt the data
        let decrypted:any = decipher.update(content, 'hex', 'utf8');
        decrypted += decipher.final('utf8');
    
        return decrypted;
    }

    // encrypts data and formats the output into a compact string
    encryptCompact(data:string):string {
        // Ecrypt the data
        let encrypted:any = this.encrypt(data);

        // Format the output
        return `${encrypted.content}.${encrypted.tag}.${encrypted.iv}`
    }

    // decrypts the output of encryptCompact
    decryptCompact(data:string):string {
        // Split the data
        let [content, tag, iv]:any = data.split('.');

        // Decrypt the data
        return this.decrypt(content, tag, iv);
    }
}