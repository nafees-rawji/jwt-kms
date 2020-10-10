export type JWTComponents = {
    header: Record<string, any>,
    payload: Record<string, any>,
    encrypted: {
        header: string,
        payload: string,
        signature: string
    }
};
