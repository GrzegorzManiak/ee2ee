import { EE2EE } from './main';

let bob = new EE2EE();

// Shared Public key //
console.log(bob.sharedPublicKey);

// Bob's public key // 
console.log(bob.aPublicKey);

let alice = new EE2EE(bob.sharedPublicKey, bob.aPublicKey);

bob.bPublicKey = alice.aPublicKey;

// generate the shared private key
let sharedPrivateKey = bob.getSharedPrivateKey();

// the private key that both parties have
console.log(sharedPrivateKey);
console.log(alice.getSharedPrivateKey());
