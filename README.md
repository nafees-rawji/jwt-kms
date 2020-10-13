# JWT-KMS

Sign and validate JWT tokens using keys stored in the AWS Key Management Service (KMS). 

Feature Todo List:
- <strike>Symmetric encryption (both parties have IAM access to KMS key)</strike>
- Asymmetic encryption (only 1 party has IAM access to KMS key)
- Unit Tests

## Requirements
- node.js 6+

## Installation
```sh
npm install jwt-kms-typescript
```

## Usage

```js
const Jwtkms = require("jwt-kms");

var jwtkms = new Jwtkms({
    aws: {
        region: "us-east-1",
        accessKeyId : process.env.AWS_ACCESS_KEY,	// Optional if set in environment
        secretAccessKey: process.env.AWS_SECRET_KEY	// Optional if set in environment
    },
    keyArn: "YOUR_AWS_KMS_KEY_ARN"
});

// Create a JWT token using a KMS key identified by a key_arn
jwtkms.sign(
    { foo: "bar" }, 
    { expires: new Date(Date.now() + 60*1000) } // Expires in 60 seconds
): Promise<JWT(string)>

// Verify that you have a valid JWT key
jwtkms.verify(token).then(function(decoded): Record<string, any>


```

## Credit 
- Created by [Nafees Rawji] (https://nafeesrawji.com)
- Inspired by [Jonathan Keebler](http://www.keebler.net)
- Inspired by [kms-jwt](https://github.com/bombbomb/kms-jwt)
