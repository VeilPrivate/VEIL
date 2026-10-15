/** Types for the vendored mlkem v2.7.0 sources (see mlkem-src/ README comment in mlkem.ts). */
export declare class MlKemError extends Error {
    constructor(e: unknown);
}
export declare class MlKem768 {
    generateKeyPair(): Promise<[Uint8Array, Uint8Array]>;
    deriveKeyPair(seed: Uint8Array): Promise<[Uint8Array, Uint8Array]>;
    encap(pk: Uint8Array, seed?: Uint8Array): Promise<[Uint8Array, Uint8Array]>;
    decap(ct: Uint8Array, sk: Uint8Array): Promise<Uint8Array>;
}
