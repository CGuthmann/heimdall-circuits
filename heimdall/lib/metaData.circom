pragma circom 2.0.0;

include "../../circomlib/circuits/eddsaposeidon.circom";
include "../../circomlib/circuits/poseidon.circom";
include "../../circomlib/circuits/comparators.circom";
include "./merkleproof.circom";
include "./hashTree.circom";

template CheckMetaDataIntegrity(branchingFactor, depth) {
	var width = branchingFactor**depth;
    signal input values[width];
    signal input signature[3];
    signal input issuerPK[2];


    signal output id;
    signal output type;
    signal output holderPK[2];
    signal output revocationRegistry;
    signal output expiration;
    signal output delegatable;
    signal output credentialRoot;

    component hash[5]; 
    for (var i = 0; i < 5; i++) {
            hash[i] = Poseidon(1);
    }
    
    component attributeTree = hashTree(branchingFactor,depth);

    hash[0].inputs[0] <== values[0];
    attributeTree.values[0] <== hash[0].out; 

    attributeTree.values[1] <== values[1];

    hash[1].inputs[0] <== values[2];
    attributeTree.values[2] <== hash[1].out;

    hash[2].inputs[0] <== values[3];
    attributeTree.values[3] <== hash[2].out;

    attributeTree.values[4] <== values[4];

    hash[3].inputs[0] <== values[5];
    attributeTree.values[5] <== hash[3].out;

    hash[4].inputs[0] <== values[6];
    attributeTree.values[6] <== hash[4].out;
    
    attributeTree.values[7] <== 19014214495641488759237505126948346942972912379615652741039992445865937985820; 

    for(var i = 8; i < width; i++){
        attributeTree.values[i] <== values[i];
    }

    

    component eddsaVerify = EdDSAPoseidonVerifier();
    eddsaVerify.enabled <== 1;
    eddsaVerify.Ax <== issuerPK[0];
    eddsaVerify.Ay <== issuerPK[1];
    eddsaVerify.R8x <== signature[0];
    eddsaVerify.R8y <== signature[1];
    eddsaVerify.S <== signature[2];
    eddsaVerify.M <== attributeTree.root;
    
    id <== values[0];
    type <== values[1];
    holderPK[0] <== values[2];
    holderPK[1] <== values[3];
    revocationRegistry <== values[4];
    expiration <== values[5];
    delegatable <== values[6];
    credentialRoot <== attributeTree.root;
}

template CheckExpiration() {
    signal input expirationCredential;
    signal input expirationPresentation;

    component le = LessEqThan(64);
    le.in[0] <== expirationPresentation;
    le.in[1] <== expirationCredential;
    1 === le.out;
}

template Pow(n) {
    signal input base;
    signal input exponent; 

    signal output out;

    signal power[n + 1];
    signal tmp[n];
    signal tmp2[n];
    component le[n];

    power[0] <== 1;
    for (var i = 0; i < n; i++) {
        le[i] = LessEqThan(8);
        le[i].in[0] <== i + 1;
        le[i].in[1] <== exponent;
        tmp[i] <== power[i] * base;
        tmp2[i] <== (1 - le[i].out) * power[i];
        power[i + 1] <== tmp2[i] + le[i].out * tmp[i];
    }

    out <== power[n];
}

template CheckHolderBinding() {
    signal input signChallenge[3];
    signal input challenge;
    signal input holderPK[2];

    component eddsaVerify = EdDSAPoseidonVerifier();
    eddsaVerify.enabled <== 1;
    eddsaVerify.Ax <== holderPK[0];
    eddsaVerify.Ay <== holderPK[1];
    eddsaVerify.R8x <== signChallenge[0];
    eddsaVerify.R8y <== signChallenge[1];
    eddsaVerify.S <== signChallenge[2];
    eddsaVerify.M <== challenge;
}

template Div(n) {
    signal input num;
    signal input denom;

    signal output div;
    signal output mod;

    div <-- (denom != 0) ? num \ denom : 0;
    mod <-- (denom != 0) ? num % denom : 0; 
    
    component le = LessThan(n);
    le.in[0] <== mod;
    le.in[1] <== denom;
    le.out === 1;

    num === div * denom + mod;
}

template CheckRevocation(depth) {
    signal input id;
    signal input lemma[depth + 2];
    signal input path[depth];
    signal input revocationLeaf;

    signal output revoked;
    signal output revocationRoot;

    component div[3];
    for (var i = 0; i < 3; i++) {
        div[i] = Div(252);
    }

    signal leafIndex[depth];
    component powLeafIndex[depth - 1];
    div[0].num <== id;
    div[0].denom <== 252;

    leafIndex[0] <== path[0];
    for(var i = 0; i < (depth - 1); i++) {
        powLeafIndex[i] = Pow(depth);
        powLeafIndex[i].base <== 2;
        powLeafIndex[i].exponent <== i + 1;
        leafIndex[i + 1] <== leafIndex[i] + path[i + 1] * powLeafIndex[i].out;
    }

    leafIndex[depth - 1] === div[0].div;

    component hash; 
    hash = Poseidon(1);
    hash.inputs[0] <== revocationLeaf;
    hash.out === lemma[0];
    component merkleProof = MerkleProof(depth);
    merkleProof.lemma[0] <== lemma[0];
    for (var i = 0; i < depth; i++) {
            merkleProof.path[i] <== path[i];
            merkleProof.lemma[i + 1] <== lemma[i + 1];
    }	
    merkleProof.lemma[depth + 1] <== lemma[depth + 1];

    component pow = Pow(252);
    pow.base <== 2;
    pow.exponent <== div[0].mod;
    div[1].num <== revocationLeaf;
    div[1].denom <== pow.out;
    div[2].num <== div[1].div;
    div[2].denom <== 2;

    revoked <== div[2].mod;

    revocationRoot <== lemma[depth + 1];
}

template Link() {
    signal input pk[2];
    signal input challenge;

    signal output out;

    component hash = Poseidon(3);
	hash.inputs[0] <== challenge;	
	hash.inputs[1] <== pk[0];
	hash.inputs[2] <== pk[1];	
	out <== hash.out;
}
