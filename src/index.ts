import {KMS} from "aws-sdk";
import base64url from "base64url";
import {JWTKMSConfig} from "./definitions/config";
import {JWTComponents} from "./definitions/components";

class JWTKMS
{
    private kms: KMS;
    private readonly keyArn: string;

    constructor(options: JWTKMSConfig)
    {
        this.keyArn = options?.keyArn
        this.kms = new KMS(options?.aws);
    }

    sign(payload: Record<string, any>, options?: {issued_at?: Date, expires?: Date}): Promise<string>
    {
        if(!this.keyArn) throw Error("Key ARN is required");

        return new Promise(async (resolve) => {
            const headers = {
                alg: "KMS",
                typ: "JWT"
            };

            if(options?.issued_at)
            {
                payload.iat = Math.ceil( options.issued_at.getTime() / 1000 );
            }
            else if(!payload.iat)
            {
                payload.iat = Math.floor( Date.now() / 1000 );
            }

            if(options?.expires)
            {
                payload.exp = Math.ceil( options.expires.getTime() / 1000 );
            }

            const tokenComponents = {
                header: base64url( JSON.stringify(headers) ),
                payload: base64url( JSON.stringify(payload) ),
                signature: ""
            };

            const data = await this.kms.encrypt({
                Plaintext: Buffer.from(base64url(tokenComponents.header + "." + tokenComponents.payload), "base64"),
                KeyId: this.keyArn
            }).promise()

            tokenComponents.signature = data.CiphertextBlob!.toString("base64");
            const token = tokenComponents.header + "." + tokenComponents.payload + "." + tokenComponents.signature;

            return resolve(token);
        });
    }

    private static validate(token: string): JWTComponents {
        if(!token || !token.split) throw Error("Invalid token");

        const tokenComponents = token.split(".");

        if (tokenComponents.length !== 3) throw Error("Invalid token");
        const components: JWTComponents = {
            header: JSON.parse(base64url.decode(tokenComponents[0])),
            payload:  JSON.parse(base64url.decode(tokenComponents[1])),
            encrypted: {
                header: tokenComponents[0],
                payload: tokenComponents[1],
                signature: tokenComponents[2]
            }
        }

        if (components.payload.iat)
        {
            const issuedAt = new Date(components.payload.iat * 1000 - 10*60*1000); // Allow for server times that are 10 mins ahead of the local time
            if (issuedAt >= new Date()) throw Error("Token was issued after the current time");

        }

        if (components.payload.exp)
        {
            const expiresAt = new Date(components.payload.exp * 1000);

            if(expiresAt < new Date()) throw Error("Token is expired")
        }

        return components;
    }



    verify(token: string): Promise<Record<string, any>>
    {
        return new Promise(async (resolve, reject) => {
            const components = JWTKMS.validate(token);
            const data = await this.kms.decrypt({CiphertextBlob: Buffer.from(components.encrypted.signature, "base64")}).promise();
            const decryptedSignature = base64url.decode(data.Plaintext!.toString("base64"));
            if (decryptedSignature === components.encrypted.header + "." + components.encrypted.payload) return resolve(components.payload);
            return reject("Signature wasn't valid");
        });
    }
}

export default JWTKMS;
