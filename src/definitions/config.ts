export type JWTKMSConfig = {
    keyArn: string,
    aws?: {
        region?: string,
        accessKeyId?: string, // Optional if set in environment
        secretAccessKey?: string // Optional if set in environment
    },
}
