pragma circom 2.0.6;
include "../../circomlib/circuits/poseidon.circom";


//generates poseidon hashtree (k=6) with values as leaves
template hashTree(branchingFactor,depth){
    var width = branchingFactor**depth;

    
    signal input values[width];
    signal output root;

    var total = ((branchingFactor** (depth)) -1) / (branchingFactor-1);
    signal tree[total];
    component hash[total]; 
    for (var i = 0; i < total; i++) {
            hash[i] = Poseidon(branchingFactor);
    }
    var width_s = branchingFactor**(depth-1);

    for(var i = 0; i < width_s; i++){
        for(var j = 0; j < branchingFactor; j++){
            hash[i].inputs[j] <== values[branchingFactor*i + j];
        }
        tree[i] <== hash[i].out;
    }

    for(var i = 0; i < total - width_s; i++){
        for(var j = 0; j < branchingFactor; j++){
            hash[i+width_s].inputs[j] <== tree[branchingFactor*i + j];
        }
        tree[i + width_s] <== hash[i+width_s].out;
    }

    root <== tree[total-1];
}