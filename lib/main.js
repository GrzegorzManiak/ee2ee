var __classPrivateFieldSet = (this && this.__classPrivateFieldSet) || function (receiver, state, value, kind, f) {
    if (kind === "m") throw new TypeError("Private method is not writable");
    if (kind === "a" && !f) throw new TypeError("Private accessor was defined without a setter");
    if (typeof state === "function" ? receiver !== state || !f : !state.has(receiver)) throw new TypeError("Cannot write private member to an object whose class did not declare it");
    return (kind === "a" ? f.call(receiver, value) : f ? f.value = value : state.set(receiver, value)), value;
};
var __classPrivateFieldGet = (this && this.__classPrivateFieldGet) || function (receiver, state, kind, f) {
    if (kind === "a" && !f) throw new TypeError("Private accessor was defined without a getter");
    if (typeof state === "function" ? receiver !== state || !f : !state.has(receiver)) throw new TypeError("Cannot read private member from an object whose class did not declare it");
    return kind === "m" ? f : kind === "a" ? f.call(receiver) : f ? f.value : state.get(receiver);
};
var _EE2EE_instances, _EE2EE_crypto, _EE2EE_client, _EE2EE_byteArrayToBase64, _EE2EE_base64ToByteArray;
export class EE2EE {
    constructor(crypto, sPublicKey, bPublicKey) {
        // If the Shared Key, and the B public key are set.
        // I will assume that this is the client, not the server,
        // in other words, this is Alice, Bob has generated his
        // shared public key and his public key, and Alice is 
        // receiving his keys, therefor the shared private keys are
        // automatically generated.
        _EE2EE_instances.add(this);
        _EE2EE_crypto.set(this, void 0);
        _EE2EE_client.set(this, void 0);
        this.bPublicKey = undefined;
        __classPrivateFieldSet(this, _EE2EE_crypto, crypto, "f");
        // If the sPublicKey isnt set, generate a new shared key
        if (sPublicKey)
            this.sharedPublicKey = sPublicKey;
        else
            this.sharedPublicKey = crypto.createDiffieHellman(256).getPrime();
        // establish the client
        __classPrivateFieldSet(this, _EE2EE_client, crypto.createDiffieHellman(this.sharedPublicKey), "f");
        __classPrivateFieldGet(this, _EE2EE_client, "f").generateKeys();
        this.aPublicKey = __classPrivateFieldGet(this, _EE2EE_client, "f").getPublicKey();
        // if the B public key and the S Public key are provided, generate the shared private key
        if (bPublicKey && sPublicKey) {
            this.bPublicKey = bPublicKey;
            this.sharedPrivateKey = __classPrivateFieldGet(this, _EE2EE_client, "f").computeSecret(bPublicKey);
        }
    }
    // Gets the shared private key of user A and user B
    getSharedPrivateKey() {
        // If the b public key isint set, throw an error
        if (!this.bPublicKey)
            throw new Error("bPub key is not defined");
        // set the shared private key to a class variable
        this.sharedPrivateKey = __classPrivateFieldGet(this, _EE2EE_client, "f").computeSecret(this.bPublicKey);
        // return the shared private key
        return this.sharedPrivateKey;
    }
    // Encrpts the data using the established shared private key
    encrypt(data) {
        let iv = __classPrivateFieldGet(this, _EE2EE_crypto, "f").randomBytes(64), // generate a random iv using nodes crypto module
        cipher = __classPrivateFieldGet(this, _EE2EE_crypto, "f").createCipheriv('aes-256-gcm', this.sharedPrivateKey, iv), // using aes-256-gcm, the shared private key and the iv, create the cipher
        encrypted = cipher.update(data, 'utf8', 'hex'); // encrypt the data
        encrypted += cipher.final('hex');
        // convert the tag and iv to base64
        let tag64 = __classPrivateFieldGet(this, _EE2EE_instances, "m", _EE2EE_byteArrayToBase64).call(this, cipher.getAuthTag()), iv64 = __classPrivateFieldGet(this, _EE2EE_instances, "m", _EE2EE_byteArrayToBase64).call(this, iv);
        return {
            content: encrypted,
            tag: tag64,
            iv: iv64,
        };
    }
    // Decrypts the data if given the correct encrypted data, shared key, tag and iv
    decrypt(content, tag, iv) {
        // Grab the tag and iv
        tag = __classPrivateFieldGet(this, _EE2EE_instances, "m", _EE2EE_base64ToByteArray).call(this, tag);
        iv = __classPrivateFieldGet(this, _EE2EE_instances, "m", _EE2EE_base64ToByteArray).call(this, iv);
        // create the decipher using the shared private key, the tag and the iv
        let decipher = __classPrivateFieldGet(this, _EE2EE_crypto, "f").createDecipheriv('aes-256-gcm', this.sharedPrivateKey, iv);
        decipher.setAuthTag(tag);
        // finaly, decrypt the data
        let decrypted = decipher.update(content, 'hex', 'utf8');
        decrypted += decipher.final('utf8');
        return decrypted;
    }
    // encrypts data and formats the output into a compact string
    encryptCompact(data) {
        // Ecrypt the data
        let encrypted = this.encrypt(data);
        // Format the output
        return `${encrypted.content}.${encrypted.tag}.${encrypted.iv}`;
    }
    // decrypts the output of encryptCompact
    decryptCompact(data) {
        // Split the data
        let [content, tag, iv] = data.split('.');
        // Decrypt the data
        return this.decrypt(content, tag, iv);
    }
}
_EE2EE_crypto = new WeakMap(), _EE2EE_client = new WeakMap(), _EE2EE_instances = new WeakSet(), _EE2EE_byteArrayToBase64 = function _EE2EE_byteArrayToBase64(byteArray) {
    return Buffer.from(byteArray).toString('base64');
}, _EE2EE_base64ToByteArray = function _EE2EE_base64ToByteArray(base64) {
    return Buffer.from(base64, 'base64');
};
