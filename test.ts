import { EE2EE } from './main';
import crypto from 'crypto';

let bob = new EE2EE(crypto),
    bPub = bob.aPublicKey;

let alice = new EE2EE(crypto, bob.sharedPublicKey, bPub);

bob.bPublicKey = alice.aPublicKey;

bob.getSharedPrivateKey();
alice.getSharedPrivateKey();

let encrypted = bob.encryptCompact('Hello World!');
console.log(encrypted);

let decrypted = alice.decryptCompact(encrypted);
console.log(decrypted);