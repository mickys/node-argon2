Extends: https://github.com/ranisalt/node-argon2

Introduces batch hash processing inside the node cpp side of the module in order to reduce calls between js and cpp to a bare minimum.

Usage:

```
const sendBuffers = [ Buffer.from("string1"), Buffer.from("string2") ];

resultsArray = await argon2.batch(sendBuffers, options);

```

