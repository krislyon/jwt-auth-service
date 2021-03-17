const { logger } = require('./logManager');

// Create an in memory token revocation list
// (INSECURE) - should be db backed, and timeboxed
//
// TODO:
// - Keep a record of currently valid tokens
// - Drop revoked tokens after validity on them has expired

const tokenStore = {
    revocationList: []
};

const revokeToken = ( jwt ) => {
    tokenStore.revocationList.push( jwt.jti );
    if(jwt.refresh === true ){
        logger.debug(`refresh_token with identifier '${jwt.jti}' has been added to the revocation list.`);
    }else{
        logger.debug(`auth_token with identifier '${jwt.jti}' has been added to the revocation list.`);
    }
}

const isRevoked = ( tokenId ) => {
    return tokenStore.revocationList.includes(tokenId);
}

const getTokenRevocationList = () => {
    return { ...{revoked_tokens: tokenStore.revocationList} };
}


exports.revokeToken = revokeToken;
exports.isRevoked = isRevoked;
exports.getTokenRevocationList = getTokenRevocationList;
