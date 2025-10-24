export type ProofRequest = {
  secret: bigint;
  publicHash: bigint;
};

export type ProofResponse = {
  isValid: boolean;
};

export class SampleWorldlinePlugin {
  readonly circuitId: string;

  constructor(circuitId: string) {
    this.circuitId = circuitId;
  }

  async prove(request: ProofRequest): Promise<ProofResponse> {
    const isValid = request.secret * request.secret === request.publicHash;
    return { isValid };
  }
}
