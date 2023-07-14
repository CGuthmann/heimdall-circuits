pragma circom 2.0.0;

include "./merkleproof.circom";
include "./polygon.circom";

template CheckAttribute(depth) {

	var width = 6**depth;
    signal input values[width];
    signal input index[width];

    signal output attribute;

    signal index_check[width];
    signal attribute_calc[width];

    index_check[0] <== index[0];
    attribute_calc[0] <== index[0] * values[0];

    for(var i = 1; i < width; i++){
        index_check[i] <== index_check[i-1] + index[i];
        attribute_calc[i] <== attribute_calc[i-1] + index[i] * values[i];
    }

    index_check[width -1 ] === 1;

    attribute <== attribute_calc[width-1];
}

template CheckPolygon(polygonSize, depth) {

    var width = 6**depth;
    signal input location[2];
    signal input attribute[width];
    signal input index[width];
    signal input vertx[polygonSize];
    signal input verty[polygonSize];

    signal output inbound;
    signal index_check[width-1];
    signal attribute_calc[width-1];
    signal attribute_b_calc[width-1];

    index_check[0] <== index[0];
    attribute_calc[0] <== index[0] * attribute[0];
    attribute_b_calc[0] <== index[0] * attribute[1];

    for(var i = 1; i < width-1; i++){
        index_check[i] <== index_check[i-1] + index[i];
        attribute_calc[i] <== attribute_calc[i-1] + index[i] * attribute[i];
        attribute_b_calc[i] <== attribute_b_calc[i-1] + index[i] * attribute[i+1];
    }

    index_check[width - 2 ] === 1;

    component hash[2];
    hash[0] = Poseidon(1);
    hash[1] = Poseidon(1);
    hash[0].inputs[0] <== location[0];
    hash[1].inputs[0] <== location[1];
    attribute_calc[width -2] === hash[0].out;
    attribute_b_calc[width -2] === hash[1].out;
               
    component polygon = Polygon(polygonSize);

    for(var i = 0; i < polygonSize; i++) {
        polygon.vertx[i] <== vertx[i];
        polygon.verty[i] <== verty[i];
    }		

    polygon.testx <== location[0];
    polygon.testy <== location[1];

    inbound <== polygon.out;
}
