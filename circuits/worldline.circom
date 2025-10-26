pragma circom 2.1.9;

/*
Public signals (order):
 0: stfCommitment
 1: programVKey
 2: policyHash
 3: proverSetDigest
Private inputs: abi0..abi4 (160B ABI), plus the three metadata inputs.
Constraint: stfCommitment equals abi0 (bind outer proof to ABI).
*/
template Wordline() {
    // 160B ABI chunks
    signal input abi0;
    signal input abi1;
    signal input abi2;
    signal input abi3;
    signal input abi4;

    // metadata provided by the aggregator (private inputs)
    signal input programVKey_in;
    signal input policyHash_in;
    signal input proverSetDigest_in;

    // public signals
    signal output stfCommitment;
    signal output programVKey;
    signal output policyHash;
    signal output proverSetDigest;

    // constraints / copy-through
    stfCommitment <== abi0;
    programVKey   <== programVKey_in;
    policyHash    <== policyHash_in;
    proverSetDigest <== proverSetDigest_in;
}

component main = Wordline();
