const { logger } = require('./logManager');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const fs = require('fs');
const tokenStore = require('./tokenStore');

const initializeKeys = () => {
    var bufSigningKey = fs.readFileSync('keys/tokenkey_priv.pem');
    var bufVerifyKey = fs.readFileSync('keys/tokenkey_pub.pem');
    const signingKO = crypto.createPrivateKey({
        key: bufSigningKey,
        format: 'pem'
    });
    const verificationKO = crypto.createPublicKey({
        key: bufVerifyKey,
        format: 'pem'
    });
    bufSigningKey.fill('0');
    bufVerifyKey.fill('0');
    return { signingKO, verificationKO };
}

const generateJWTTokenPair = (user, signingKO ) => {
    var authTokenOpts = {
        algorithm: 'ES512',
        jwtid: crypto.randomBytes(16).toString('hex'),
        expiresIn: '1m',
        notBefore: '-1ms',
    }
    var refreshTokenOpts = {
        algorithm: 'ES512',
        jwtid: crypto.randomBytes(16).toString('hex'),
        expiresIn: '2m',
        notBefore: '-1ms',
    }
    var authToken = { userId: user.userId, roles: user.roles };
    var refreshToken = { userId: user.userId, refresh: true };
    const signedAuthToken = jwt.sign( authToken, signingKO, authTokenOpts );
    const signedRefreshToken = jwt.sign( refreshToken, signingKO, refreshTokenOpts );

    return { signedAuthToken, signedRefreshToken };
}

const validateRefreshToken = (token,verificationKO,verifyOpts) => {
    var options = {
        algorithms: ["ES512"],
        maxAge: "10m",
        ...verifyOpts
    };

    // Validate JWT Refresh Token
    var decoded;
    try{
        decoded = jwt.verify( token, verificationKO, options );
    }catch(err){
        logger.warn(`Refresh Failed: refresh_token failed validation. (${err})`);
        throw(err);
    }

    // Ensure JWT Refresh Token has not been previously revoked
    if( tokenStore.isRevoked(decoded) ){
        const errMsg = `Refresh Failed: refresh_token was previously revoked (attempted re-use).`;
        logger.warn(errMsg);
        throw( {message: errMsg});
    }

    // Ensure Token is a refresh token
    if( decoded.refresh != true ){
        const errMsg = `Refresh Failed: refresh_token validated but was not a refresh token. (attempted subversion).`;
        logger.warn(errMsg)
        throw({ message: errMsg });
    }
    logger.debug('Refresh token validated successfully.');
    return decoded;
}

const validateAuthenticationToken = (token,verificationKO,verifyOpts) => {
    var options = {
        algorithms: ["ES512"],
        maxAge: "5m",
        ...verifyOpts
    };

    // Validate JWT Refresh Token
    var decoded;
    try{
        decoded = jwt.verify( token, verificationKO, options );
    }catch(err){
        logger.warn(`Validation Failed: auth_token failed validation. (${err})`);
        throw(err);
    }

    // Ensure token has not been previously revoked
    if( tokenStore.isRevoked(decoded) ){
        const errMsg = `Refresh Failed: auth_token was previously revoked (attempted re-use).`;
        logger.warn(errMsg);
        throw({message: errMsg});
    }
    logger.debug('Authentication token validated successfully');
    return decoded;
}

exports.initializeKeys = initializeKeys;
exports.generateJWTTokenPair = generateJWTTokenPair;
exports.validateRefreshToken = validateRefreshToken;
exports.validateAuthenticationToken = validateAuthenticationToken;