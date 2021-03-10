const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const userStore = require('./userStore');

// Initialize Store with default users
// (INSECURE) - should be db backed, and a real user store
userStore.createUser( 'lyonk', 'test', ['admin','user'] );
userStore.createUser( 'test', 'test', ['user'] );

// Create an in memory token revocation list
// (INSECURE) - should be db backed, and timeboxed
const tokenRevocationList = [];

// Generate a token signing secret
// (INSECURE) - should be leveraging public key not a single secret.

const tokenSigningSecret = crypto.randomBytes(32).toString('hex');
console.log('Token Signing Secret: ' + tokenSigningSecret );

const handleAuthentication = async(req,res) => {
    if( !req.body.userId ){
        console.log('P1 Authentication Failed: req.body.userId was not found');
        res.sendStatus(401);
    }

    const user = userStore.getUser(req.body.userId);
    if( !user ){
        console.log(`P1 Authentication Failed: User ${req.body.userId} does not exist.`);
        res.sendStatus(401);
    }

    if( !req.body.pwHash ){
        console.log('P1 Authentication Complete: Returning Salt');
        res.status(200).json( { salt: user.pwSalt } );
        return;
    }

    // Validate password hash
    if( req.body.pwHash !== user.pwHash ){
        console.log('P2 Authentication Failed: password hashes did not match.')
        res.sendStatus(401);
        return;
    }

    // User is now Authenticated.
    console.debug(`User '${user.userId}' Authenticated Successfully, returning JWT token pair.`);
    const {signedAuthToken, signedRefreshToken} = generateJWTTokenPair(user);

    // Set a client-side cookie with the refresh token
    var cookieOpts = {
        httpOnly: true,
        sameSite: 'lax',
//      secure: true,
        maxAge: 10 * 60 * 1000,
    }
    res.status(200)
        .cookie('refresh_token', signedRefreshToken, cookieOpts )
        .json( { auth_token: signedAuthToken });
}

const handleAuthenticationRefresh = async(req,res) => {
    // Validate presence of Refresh Token
    if( !req.cookies.refresh_token ){
        console.log('Refresh Failed: No refresh_token found. (req.cookies.refresh_token missing from request).');
        res.sendStatus(401);
        return;
    }

    // Validate JWT Refresh Token
    var token;
    try{
        token = validateRefreshToken( req.cookies.refresh_token );
    }catch(err){
        res.sendStatus(401);
        return;
    }

    // Validation was successful: invalidate current refresh token and issue new tokens.
    revokeToken( token );
    const user = userStore.getUser(token.userId);
    const {signedAuthToken, signedRefreshToken} = generateJWTTokenPair(user);

    // Update client-side cookie with new refresh token, and return result
    var cookieOpts = {
        httpOnly: true,
        sameSite: 'lax',
    //      secure: true,
        maxAge: 10 * 60 * 1000,
    }

    console.log('auth_token/refresh_token successfully refreshed.');
    res.status(200)
        .cookie('refresh_token', signedRefreshToken, cookieOpts )
        .json( { auth_token: signedAuthToken });

    return;
}

const handleRequstValidation = async(req,res,next) => {
    if( !req.headers.authorization ){
        console.log('Request Validation Failed: Unable to locate authorization header.');
        res.sendStatus(401);
        return;
    }
    const token = req.headers.authorization.split(' ')[1];
    try{
        const decoded = validateAuthenticationToken(token);
        const user = userStore.getUser(decoded.userId);
        if( !user ){
            console.log(`Request Validation Failed: User ${decoded.userId} does not exist.`);
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
    var errState = false;

    if( req.headers.authorization ){
        try{
            const token = req.headers.authorization.split(' ')[1];
            const decoded = validateAuthenticationToken(token,{ ignoreExpiration: true });
            revokeToken(decoded);
        }catch(err){
            errState = true;
        }
    }

    if( req.cookies.refresh_token ){
        try{
            const decoded = validateRefreshToken(req.cookies.refresh_token, { ignoreExpiration: true});
            revokeToken(decoded);
        }catch(err){
            errState = true;
        }
    }

    if( errState ){
        res.sendStatus(500);
    }else{
        res.sendStatus(200);
    }
};

const handleTRLRequest = async(req,res) => {
    res.status(200).json( { revoked_tokens: tokenRevocationList });
}

const revokeToken = (jwt) => {
    tokenRevocationList.push(jwt.jti);
    if(jwt.refresh === true ){
        console.log(`refresh_token with identifier '${jwt.jti}' has been added to the revocation list.`);
    }else{
        console.log(`auth_token with identifier '${jwt.jti}' has been added to the revocation list.`);
    }
}

const checkRevocation = (jwt) => {
    return tokenRevocationList.includes(jwt.jti);
}

const validateRefreshToken = (token,verifyOpts) => {
    var verifyOpts = {
        algorithms: ["HS256"],
        maxAge: "10m",
        ...verifyOpts
    };

    // Validate JWT Refresh Token
    var token;
    try{
        token = jwt.verify( token, tokenSigningSecret, verifyOpts );
    }catch(err){
        console.log(`Refresh Failed: refresh_token failed validation. (${err})`);
        throw(err);
    }

    // Ensure JWT Refresh Token has not been previously revoked
    if( checkRevocation(token) ){
        const errMsg = `Refresh Failed: refresh_token was previously revoked (attempted re-use).`;
        console.log(errMsg);
        throw( {message: errMsg});
    }

    // Ensure Token is a refresh token
    if( token.refresh != true ){
        const errMsg = `Refresh Failed: refresh_token validated but was not a refresh token. (attempted subversion).`;
        console.log(errMsg)
        throw({ message: errMsg });
    }
    console.log('Refresh token validated successfully.');
    return token;
}

const validateAuthenticationToken = (token,verifyOpts) => {
    var verifyOpts = {
        algorithms: ["HS256"],
        maxAge: "5m",
        ...verifyOpts
    };

    // Validate JWT Refresh Token
    var token;
    try{
        token = jwt.verify( token, tokenSigningSecret, verifyOpts );
    }catch(err){
        console.log(`Refresh Failed: auth_token failed validation. (${err})`);
        throw(err);
    }

    // Ensure token has not been previously revoked
    if( checkRevocation(token) ){
        const errMsg = `Refresh Failed: auth_token was previously revoked (attempted re-use).`;
        console.log(errMsg);
        throw({message: errMsg});
    }
    console.log('Authentication token validated successfully');
    return token;
}

const generateJWTTokenPair = (user) => {
    var authTokenOpts = {
        algorithm: 'HS256',
        jwtid: crypto.randomBytes(8).toString('hex'),
        expiresIn: '5m',  // 5 minutes
        notBefore: '-1ms',
    }
    var refreshTokenOpts = {
        algorithm: 'HS256',
        jwtid: crypto.randomBytes(8).toString('hex'),
        expiresIn: '10m',  // 10 minutes
        notBefore: '-1ms',
    }
    var authToken = { userId: user.userId, roles: user.roles };
    var refreshToken = { userId: user.userId, refresh: true };
    const signedAuthToken = jwt.sign( authToken, tokenSigningSecret, authTokenOpts );
    const signedRefreshToken = jwt.sign( refreshToken, tokenSigningSecret, refreshTokenOpts );

    // Log the newly minted tokens
    // console.log('auth_token: ' + signedAuthToken );
    // console.log('refresh_token: ' + signedRefreshToken );

    return { signedAuthToken, signedRefreshToken };
}

exports.handleAuthentication = handleAuthentication;
exports.handleAuthenticationRefresh = handleAuthenticationRefresh;
exports.handleRequestValidation = handleRequstValidation;
exports.handleLogout = handleLogout;
exports.handleTRLRequest = handleTRLRequest;

exports.revokeToken = revokeToken;
exports.checkRevocation = checkRevocation;