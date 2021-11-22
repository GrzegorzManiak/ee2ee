import { EE2EE } from './main';
import crypto from 'crypto';

let bob = new EE2EE(crypto),
    bPub = bob.getPublicKey();

let alice = new EE2EE(crypto, bob.sharedPublicKey, bPub);

bob.bPublicKey = alice.getPublicKey();

bob.getSharedPrivateKey();
alice.getSharedPrivateKey();

let encrypted = bob.encrypt('Hello World!').complete;
console.log(encrypted);

let decrypted = alice.decryptCompact(encrypted);
console.log(decrypted);