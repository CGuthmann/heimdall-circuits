pragma circom 2.0.1;

include "./circomlib/circuits/poseidon.circom";
template poseidonHasher(n){
    signal input a;
    signal output d;

    component hasher[n];
    hasher[0] = Poseidon(1);
    hasher[0].inputs[0] <== a;
    for(var i = 1; i < n; i++){
        hasher[i] = Poseidon(1);
        hasher[i].inputs[0] <== hasher[i-1].out;
    }

    d <== hasher[n-1].out;
}

component main = poseidonHasher(100);
