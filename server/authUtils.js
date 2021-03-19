const { logger } = require('./logManager');
const userStore = require('./userStore');
const crypto = require('crypto');

const generateAuthChallenge = (userId, signingKO) => {
    var user = userStore.getUser(userId);

    if( !user ){
        // User was not found in our user store, return a dummy salt to prevent enumeration.
        logger.warn(`Authentication Failed: User ${req.body.userId} does not exist, returning dummy salt.`);
        user = userStore.generateDummySaltValue(userId);
    }

    // Create Nonce & Signature
    const timestamp = Date.now().toString();
    const sign = crypto.createSign('SHA256');
    sign.update( timestamp );
    sign.update( user.userId );
    sign.end();
    const nonceSig = sign.sign( signingKO, 'hex' );

    // Return the Auth Challenge package
    return {
        salt:  user.pwSalt,
        nonce: timestamp,
        sig: nonceSig
    };
}

const validateChallengeResponse = (req, verificationKO) => {
    var user = userStore.getUser(req.body.userId);

    // Validate nonce signature.
    const verify = crypto.createVerify('SHA256');
    verify.update( req.body.nonce );
    verify.update( user.userId );
    verify.end();
    if( !verify.verify( verificationKO , req.body.sig, 'hex' ) ){
        logger.warn('Authentication Failed: returned nonce did not match signature')
        return false;
    }

    // Validate timestamp is within window.
    const delta = Date.now() - req.body.nonce;
    if( delta < 0 || delta > 10000){
        logger.warn(`Authentication Failed: Stale auth challenge (delta == ${delta})`);
        return false;
    }

    // Create the validation hash
    const hash = crypto.createHash('sha256');
    hash.update( req.body.nonce + user.pwHash );
    const validationHash = hash.digest().toString('hex');

    // Validate password hash
    if( req.body.pwHash === validationHash ){
        // Success
        return true;
    }

    logger.warn('Authentication Failed: password hashes did not match.')
    return false;
};


exports.generateAuthChallenge = generateAuthChallenge;
exports.validateChallengeResponse = validateChallengeResponse;