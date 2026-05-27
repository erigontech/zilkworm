---
title: Private Enterprise EVM Chain
description: Use Zilkworm's privacy-preserving proofs to run a permissioned EVM chain for banks, asset managers, and regulated workflows.
sidebar_position: 3
---


When you don't need the blocks to verify its correctness, the interesting side-benefit is keeping transactions and their data private. Ergo, Zilkworm has a neat use case for Private Enterprise blockchains that use EVMs. Let's explore.

### Private and a Blockchain?

Historically blockchains have been a symbol of transparency, being permissionless and decentralized. But they are much more than that. Nowadays EVM-based chains manage trillions of dollars of assets securely every month. The security that's guaranteed by mathematics, economics and a robust ecosystem around blockchains.

Naturally, after 10 years in thriving existence in the domain of secure trade, "banking", and various other use cases, it has a huge potential for larger Enterprises.

But not all use cases can be as simple as deploying a smart contract on Ethereum or an L2 due to concerns of security, regulation, privacy, business needs and other reasons. That's why the next major chunk of this economy would have to aboard the blockchain ship in a slightly different way.

### A state root, a proof, and a long lever to move the world

An Ethereum node is in the middle of an adversarial environment. Any or all of its peers could be malicious, or in other words, feed data that's incorrect. We have several mechanisms to ensure that the correct chain is the one that has been correctly processed and is also seen by the super-majority of other nodes across the globe.

In the heart of this "correct" view of the world is the State Root. It is the merkle root of all state data. This tiny 32-byte string ensures that all of the accounting is correct to the last dots and crosses. The merkle root comes out wildly different for the tiniest of modifications of the data. In a way the whole world is constantly looking at everything just to ensure that they are seeing this correct state root.

Looked at another way, this also means if I can mathematically prove to you that an "old" state root goes to a "new" state root only after correct EVM execution, you should be convinced of the new state root without the being wholly aware of what is going on in the world. And that's why a proof + state-root is solid grounds enough to have a blockchain (safely) moving.

### A swift Example!

Let's say you, Alice, have a 100 units of an asset with ZBank and now want to transfer it to your account in FBank.&#x20;

Traditionally, this uses a fancy version of "trust-me-bro" consensus between the two banks like SWIFT. Meaning, you may not be allowed this transfer or a 100 other things. An easier path would be not having that asset in the first place, but let's say ZBank and YBank have both decided to be cypherpunks now and they run their own private blockchains and would settle interbank on Ethereum!

The transactions would look something like this

Alice -> ZBank chain: tx (send YBank 100, credit Alice)

The accounting it will create in ZBank's chain would be

ZBank - Alice: (100)\
YBank - Alice: 100\
ZBank - YBank: Settle 100

Now for the settlement process, two ways can work

* Direct Ethereum settling\
  Alice or YBank can now submit a ZK proof to a specific contract in Ethereum regarding the fact that Alice caused a ZBank - YBank: Settle 100 event
* Submit  a proof on YBank's chain\
  Alice can directly submit a ZK proof on YBank chain that it transferred the 100 units of asset, it'll be YBank's responsibility to clear the balance on ZBank chain.

### How do you generate these proofs?

The previous example was somewhat cliche but in general proofs are just hidden EVM smart contract execution. So the way to enable such functionality would be to write good smart contracts that can do these things already - such as existing bridge contracts. Then it is a simple matter of submitting full block proofs and/or proofs on certain transactions.

One great feature of the ZK proofs generated with ZKVMs these days is "public outputs" that embed certain values that come out after processing. The public outputs, for instance, can be the values of "settlement" between ZBank and YBank in the previous example.

From the block proof alone it can't be inferred if an extraneous settlement is pending. So, an interbank settlement would need to see a certain transaction trace and the public output. This is where Zilkworm's transaction prover comes in that can be configured to output public outputs on re-running certain transactions.

### Big talk, does it work?

It works, yes. But if you are interested in a partnership in exploring the most straightforward and robust Zero-Knowledge proofs on EVMs, give us a ping!
