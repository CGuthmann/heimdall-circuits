pragma circom 2.0.0;

include "../../circomlib/circuits/poseidon.circom";
include "../../circomlib/circuits/comparators.circom";

template HashLeftRight() {
	signal input left;
	signal input right;

	signal output hash;

	component hasher = Poseidon(2);
	hasher.inputs[0] <== left;
	hasher.inputs[1] <== right;
	hash <== hasher.out;
}

template Selector() {
	signal input input_elem;
	signal input lemma_elem;
	signal input path_elem;

	signal output left;
	signal output right;

	signal left_selector_1;
	signal left_selector_2;
	signal right_selector_1;
	signal right_selector_2;

	path_elem * (1 - path_elem) === 0;

	left_selector_1 <== (1 - path_elem) * input_elem;
	left_selector_2 <== (path_elem) * lemma_elem;
	right_selector_1 <== (path_elem) * input_elem;
	right_selector_2 <== (1 - path_elem) * lemma_elem;

	left <== left_selector_1 + left_selector_2;
	right <== right_selector_1 + right_selector_2;
}

template MerkleProof(depth) {

	signal input lemma[depth + 2];
	signal input path[depth];

	component selectors[depth];
	component hashers[depth];

	selectors[0] = Selector();
	hashers[0] = HashLeftRight();
	selectors[0].input_elem <== lemma[0];
	selectors[0].lemma_elem <== lemma[1];
	selectors[0].path_elem <== path[0];	
	hashers[0].left <== selectors[0].left;
	hashers[0].right <== selectors[0].right;

	for (var i = 1; i < depth; i++) {
		selectors[i] = Selector();
		hashers[i] = HashLeftRight();

		selectors[i].path_elem <== path[i];
		selectors[i].lemma_elem <== lemma[i + 1];
		selectors[i].input_elem <== hashers[i - 1].hash; 
		
		hashers[i].left <== selectors[i].left;
		hashers[i].right <== selectors[i].right;
	}

	lemma[depth + 1] === hashers[depth - 1].hash;
}
// Receives already hashed leaves
template MerkleTree(depth) {
	var width = 2 ** depth;
	
	signal input data[width];
	
	signal output root;
	
	var nodes = 2 ** (depth + 1) - 1;
	component hashLR[(nodes >> 1)];
    for (var i = 0; i < (nodes >> 1); i++) {
        hashLR[i] = HashLeftRight();
    }

	signal nodeHashes[nodes];
	for (var i = 0; i < width; i++) {
        nodeHashes[i] <== data[i];
    }
	var w = width;
	w = w >> 1;
	var offset = 0;
	var hashCounter = 0;
	while (w > 0) {
		for (var i = 0; i < w; i++) {
			var j = 2 * i + offset;
			hashLR[hashCounter].left <== nodeHashes[j];
			hashLR[hashCounter].right <== nodeHashes[j + 1];
			nodeHashes[w * 2 + i + offset] <== hashLR[hashCounter].hash;
			hashCounter++;
		}
		offset = offset + w * 2;
		w = w >> 1;
	}	
	root <== nodeHashes[nodes - 1];
}