const { logger } = require('./logManager');
const userStore = require('./userStore');
const tokenStore = require('./tokenStore');
const { initializeKeys, generateJWTTokenPair, validateRefreshToken, validateAuthenticationToken } = require('./tokenUtils');

logger.warn("*****************************************************************************");
logger.warn("Demo implmentation requiring further hardening.  Do not deploy to production.");
logger.warn("- Update self-signed SSL Certificates");
logger.warn("- Implement database backed token revocation list");
logger.warn("- Implement database backed user storage and roles.");
logger.warn("- Enhance logging and track token status.");
logger.warn("- Update CORS Configuration");
logger.warn("- Update to use secure PRNG");
logger.warn("- Implement nonce value in context");
logger.warn("- Implement route to retrieve public key");
logger.warn("- Support multiple verification keys");
logger.warn("*****************************************************************************");

// Initialize Store with default users
// (INSECURE) - should be db backed, and a real user store
userStore.createUser( 'lyonk', 'test', ['admin','user'] );
userStore.createUser( 'test', 'test', ['user'] );

const tokenKeypair = initializeKeys();

// Generate a token signing secret
// (INSECURE) - should be leveraging public key not a single secret.
// const tokenSigningSecret = crypto.randomBytes(32).toString('hex');
// logger.debug('Token Signing Secret: ' + tokenSigningSecret );

const handleAuthentication = async(req,res) => {
    logger.debug('Authentication Request Received - beginning auth.');

    if( !req.body.userId ){
        logger.warn('Authentication Failed: req.body.userId was not found');
        res.status(500).json( { message: "userId was not found in the request body." } );
        return;
    }

    const user = userStore.getUser(req.body.userId);
    if( !user ){
        if( !req.body.pwHash ){
            // User was not found in our user store, return a dummy salt to prevent enumeration.
            logger.warn(`Authentication Failed: User ${req.body.userId} does not exist, returning dummy salt.`);
            res.status(200).json( userStore.generateDummySaltValue( req.body.userId ) );
            return;
        }else{
            logger.warn(`Authentication Failed: User ${req.body.userId} does not exist, returning 401-Unauthorized.`);
            // User still isn't found in the store, but they've now responded to the dummy hash
            // send them an unauthorized request, as if it was a bad password.
            res.sendStatus(401);
            return;
        }
    }

    if( !req.body.pwHash ){
        logger.debug('Authentication Initiated: Returning Salt');
        res.status(200).json( { salt: user.pwSalt } );
        return;
    }

    // Validate password hash
    if( req.body.pwHash !== user.pwHash ){
        logger.warn('Authentication Failed: password hashes did not match.')
        res.sendStatus(401);
        return;
    }

    // User is now Authenticated.
    logger.info(`User '${user.userId}' Authenticated Successfully, issuing auth_token/refresh_token.`);
    const {signedAuthToken, signedRefreshToken} = generateJWTTokenPair(user,tokenKeypair.signingKO);

    // Set a client-side cookie with the refresh token
    var cookieOpts = {
        httpOnly: true,
        sameSite: 'None',
        secure: true,
        maxAge: 2 * 60 * 1000,
    }
    res.status(200)
        .cookie('refresh_token', signedRefreshToken, cookieOpts )
        .json( { auth_token: signedAuthToken });
}

const handleAuthenticationRefresh = async(req,res) => {
    logger.debug('Refresh Request Received - attempting refresh.');

    // Validate presence of Refresh Token
    if( !req.cookies.refresh_token ){
        logger.warn('Refresh Failed: No refresh_token found. (req.cookies.refresh_token missing from request).');
        res.sendStatus(401);
        return;
    }

    // Validate JWT Refresh Token
    var token;
    try{
        token = validateRefreshToken(req.cookies.refresh_token,tokenKeypair.verificationKO);
    }catch(err){
        res.sendStatus(401);
        return;
    }

    // Validation was successful: invalidate current refresh token and issue new tokens.
    tokenStore.revokeToken( token );
    const user = userStore.getUser(token.userId);
    const {signedAuthToken, signedRefreshToken} = generateJWTTokenPair(user,tokenKeypair.signingKO);

    // Update client-side cookie with new refresh token, and return result
    var cookieOpts = {
        httpOnly: true,
        sameSite: 'None',
        secure: true,
        maxAge: 2 * 60 * 1000,
    }

    logger.info(`User '${user.userId}' successfully refreshed auth_token/refresh_token.`);
    res.status(200)
        .cookie('refresh_token', signedRefreshToken, cookieOpts )
        .json( { auth_token: signedAuthToken });

    return;
}

const handleRequestValidation = async(req,res,next) => {
    if( !req.headers.authorization ){
        logger.warn('Request Validation Failed: Unable to locate authorization header.');
        res.sendStatus(401);
        return;
    }
    const token = req.headers.authorization.split(' ')[1];
    try{
        const decoded = validateAuthenticationToken(token,tokenKeypair.verificationKO);
        const user = userStore.getUser(decoded.userId);
        if( !user ){
            logger.warn(`Request Validation Failed: User '${decoded.userId}' does not exist.`);
            res.sendStatus(401);
        }
        req.user = user;
        next();
    }catch(err){
        res.sendStatus(401);
        return;
    }

};

const handleLogout = async(req,res) => {
    logger.debug('Logout Request Received - beginning logout.');

    var errState = false;
    var decoded;
    if( req.headers.authorization ){
        try{
            const token = req.headers.authorization.split(' ')[1];
            decoded = validateAuthenticationToken(token,tokenKeypair.verificationKO,{ ignoreExpiration: true });
            tokenStore.revokeToken(decoded);
        }catch(err){
            errState = true;
        }
    }

    if( req.cookies.refresh_token ){
        try{
            decoded = validateRefreshToken(req.cookies.refresh_token,tokenKeypair.verificationKO,{ ignoreExpiration: true});
            tokenStore.revokeToken(decoded);
        }catch(err){
            errState = true;
        }
    }

    if( decoded ){
        logger.info(`User '${decoded.userId}' successfully logged out.`);
    }

    if( errState ){
        res.sendStatus(500);
    }else{
        res.sendStatus(200);
    }
};

const handleTRLRequest = async(req,res) => {
    res.status(200).json( tokenStore.getTokenRevocationList() );
}

exports.handleAuthentication = handleAuthentication;
exports.handleAuthenticationRefresh = handleAuthenticationRefresh;
exports.handleRequestValidation = handleRequestValidation;
exports.handleLogout = handleLogout;
exports.handleTRLRequest = handleTRLRequest;