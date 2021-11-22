EE2EE
=====
### Easy End 2 End Encryption
This is just me learning, I wouldn't use this for anything.

#### [1.a] Init (Orgin)
Import node's crypto module and the EE2EE module, pass the crypto module to EE2EE.
Since we didn't provide any *shared public key*, EE2EE will generate one for us, also, it will automatically generate Bob's public key.

```typescript
import { EE2EE } from './main';
import crypto from 'crypto';

let bob = new EE2EE(crypto);

// Shared Public key //
console.log(bob.sharedPublicKey);

// Bob's public key // 
console.log(bob.aPublicKey);
```

#### [1.b] Init (Client)
Import node's crypto module and the EE2EE module, pass the crypto module to EE2EE.
Since we reciveing, we will define the Orgin's *Shared Public key* and their *Public key*

```typescript
import { EE2EE } from './main';
import crypto from 'crypto';

let alice = new EE2EE(crypto, sharedPublicKey, aPublicKey);

// Shared Public key //
console.log(alice.sharedPublicKey);

// Alice's public key // 
console.log(alice.aPublicKey);
```

#### [2.a] Getting the shared private key (Orgin)
Once you recive the Client's (B) public key, you'll be able to define it, and generate
Bob's shared private key.

```typescript
bob.bPublicKey = clientPublicKey;

// generate the shared private key
let sharedPrivateKey = bob.getSharedPrivateKey();

// the private key that both parties have
console.log(sharedPrivateKey);
```

#### [2.b] Getting the shared private key (Client)
Since you've already recived all the required keys to generate your *private shared key*, it's automatically generated for you.

```typescript
// generate the shared private key
let sharedPrivateKey = alice.getSharedPrivateKey();

// the private key that both parties have
console.log(sharedPrivateKey);
```

#### Encrypt and Decrypt some data!
Now that you have generated the shared private keys, you can use the internal
*encrypt, encryptCompact, decrypt and decryptCompact* functions.
```typescript
//Encrypt takes in a strign as its only paramater

let encrypted = bob.encrpyt('hello world!');
//We have just encrypted 'hellow world' with the shared private key
//this will return and object containing the encrypted Data, Iv and Tag
//{
//    content: encrypted,
//    tag: tag64,
//    iv: iv64,
//};

// You can then decrypt it, we will use Alice for this example
let decrypted = alice.decrypt(encrypted.content, encrypted.tag, encrypted.iv);

//if we print this, we should see 'hello world!'
console.log(decrypted);
```
or
```typescript
//You can just format everything into one string using 'encryptCompact'

let encrypted = bob.encryptCompact('hello world!');
//This will return a string, formated as such 'encryptedData.tag.iv'
//Encoded in Base64

//You can than just take that formated string, and decrypt it with 'decryptCompact'
let decrypted = alice.decryptCompact(encrypted);

//if we print this, we should see 'hello world!'
console.log(decrypted);
```
------
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
