pragma circom 2.0.0;

include "../../lib/metaData.circom";
include "../../lib/contentData.circom";

template DelegationPresentation(branchingFactor, depth, revocationDepth) {
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
	signal output linkForth; //8
	signal output values_o[width]; // 9..
	/*
	* Meta Calculations
	*/
	// Begin - Check Meta Integrity
	component checkMetaDataIntegrity = CheckMetaDataIntegrity(branchingFactor, depth);

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

	/*
	* Content Calculations
	*/
	component getLinkForth = Link();
	getLinkForth.challenge <== challenge;
	getLinkForth.pk[0] <== checkMetaDataIntegrity.holderPK[0];
	getLinkForth.pk[1] <== checkMetaDataIntegrity.holderPK[1];
	linkForth <== getLinkForth.out;

	challenge_o <== challenge;
	expiration_o <== expiration;
	
	for(var i = 0; i< width; i++){
		values_o[i] <== values[i] * toPublish[i];
		0 === toPublish[i] * (1 - toPublish[i]);
	}
	
}

component main = DelegationPresentation(6, 2, 13);
