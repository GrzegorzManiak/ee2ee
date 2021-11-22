EE2EE
=====
### Easy End 2 End Encryption
This is just me learning, I wouldn't use this for anything.

Demo code
```typescript
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
```