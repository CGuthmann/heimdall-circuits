pragma circom 2.0.0;


include "../../lib/metaData.circom";
include "../../lib/contentData.circom";

template AttributePresentation(branchingFactor,depth, revocationDepth) {
	/*
	* Private Inputs
	*/
	// Meta
	var width = branchingFactor**depth;
	signal input values[width]; 
	signal input signatureMeta[3];
	signal input issuerPK[2];

	signal input expiration;

	signal input pathRevocation[revocationDepth];
	signal input lemmaRevocation[revocationDepth + 2];
	signal input revocationLeaf;

	signal input challenge; 
	signal input signChallenge[3];

	// Content
	signal input toPublish[width];

	
	signal output type;//0
	signal output revocationRoot; //1
	signal output revocationRegistry; //2
	signal output revoked; //3
	signal output linkBack; //4
	signal output delegatable;//5
	signal output challenge_o; //6
	signal output expiration_o; //7
	signal output values_o[width]; // 8..
	/*
	* Meta Calculations
	*/
	// Begin - Check Meta Integrity
	component checkMetaDataIntegrity = CheckMetaDataIntegrity(branchingFactor,depth);

	checkMetaDataIntegrity.issuerPK[0] <== issuerPK[0];
	checkMetaDataIntegrity.issuerPK[1] <== issuerPK[1];

	checkMetaDataIntegrity.signature[0] <== signatureMeta[0];
	checkMetaDataIntegrity.signature[1] <== signatureMeta[1];
	checkMetaDataIntegrity.signature[2] <== signatureMeta[2];

	
	for(var i = 0; i < width; i++) {
		checkMetaDataIntegrity.values[i] <== values[i];
	}

	type <== checkMetaDataIntegrity.type;
	revocationRegistry <== checkMetaDataIntegrity.revocationRegistry;
	delegatable <== checkMetaDataIntegrity.delegatable;
	

	// Begin - Check Expiration
	component checkExpiration = CheckExpiration();
	checkExpiration.expirationCredential <== values[5];
	checkExpiration.expirationPresentation <== expiration;
	// End - Check Expiration

	// Begin - Check Revocation
	component checkRevocation = CheckRevocation(revocationDepth);
	checkRevocation.id <== checkMetaDataIntegrity.id;
	checkRevocation.revocationLeaf <== revocationLeaf;
	checkRevocation.lemma[0] <== lemmaRevocation[0];
	for(var i = 0; i < revocationDepth; i++) {
		checkRevocation.path[i] <== pathRevocation[i];
		checkRevocation.lemma[i + 1] <== lemmaRevocation[i + 1];
	}
	checkRevocation.lemma[revocationDepth + 1] <== lemmaRevocation[revocationDepth + 1];
	revocationRoot <== lemmaRevocation[revocationDepth + 1];
	revoked <== checkRevocation.revoked;
	// End - Check Revocation

	component getLinkBack = Link();
	getLinkBack.challenge <== challenge;
	getLinkBack.pk[0] <== issuerPK[0];
	getLinkBack.pk[1] <== issuerPK[1];
	linkBack <== getLinkBack.out;


	//Begin - Holder Binding
	component checkHolderBinding = CheckHolderBinding();
	checkHolderBinding.signChallenge[0] <== signChallenge[0];
	checkHolderBinding.signChallenge[1] <== signChallenge[1];
	checkHolderBinding.signChallenge[2] <== signChallenge[2];
	checkHolderBinding.challenge <== challenge;
	checkHolderBinding.holderPK[0] <== values[2];
	checkHolderBinding.holderPK[1] <== values[3];
	//End - Holder Binding
	/*
	* Content Calculations
	*/
	challenge_o <== challenge;
	expiration_o <== expiration;
	
	for(var i = 0; i< width; i++){
		values_o[i] <== values[i] * toPublish[i];
		0 === toPublish[i] * (1 - toPublish[i]);
	}
}


component main = AttributePresentation(16,1, 13);
