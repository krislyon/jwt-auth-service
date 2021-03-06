const axios = require('axios');
const { logger } = require('./logManager');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const https = require('https');

logger.warn("*****************************************************************************");
logger.warn("Demo implmentation requiring further hardening.  Do not deploy to production.");
logger.warn("- Update self-signed SSL Certificates");
logger.warn("- Update CORS Configuration");
logger.warn("- Support multiple verification keys");
logger.warn("*****************************************************************************");

const tokenSigningAlgorithm = "ES512"
const authTokenExpiry = '30m';
const refreshTokenExpiry = '60m';

// Load token signing keys
const requestVerificationKey = () => {

    const httpsAgent = new https.Agent({
        rejectUnauthorized: false,
        // ca: fs.readFileSync("./resource/bundle.crt"),
        // cert: fs.readFileSync("./resrouce/thirdparty.crt"),
        // key: fs.readFileSync("./resource/key.pem"),
    })

    const options = {
        baseURL: 'https://localhost:3000',
        json: true,
        headers: {
          'Content-Type': 'application/json',
        },
        httpsAgent
    }
    return axios.get('/tokenverificationkey', options )
    .then( response => {
        const tokenVerificationKey = crypto.createPublicKey({
            key: response.data.public_key,
        })
        logger.info('Loaded Token Verification Key from Auth Server.');
        return tokenVerificationKey;
    })
    .catch( err => {
        console.dir(err);
        logger.error(err);
    });
};

const validateAuthenticationToken = (token,verificationKO,verifyOpts) => {
    var options = {
        algorithms: [ tokenSigningAlgorithm ],
        maxAge: authTokenExpiry,
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
    // if( tokenStore.isRevoked(decoded) ){
    //     const errMsg = `Refresh Failed: auth_token was previously revoked (attempted re-use).`;
    //     logger.warn(errMsg);
    //     throw({message: errMsg});
    // }
    logger.debug('Authentication token validated successfully');
    return decoded;
}


const handleRequestValidation = async(req,res,next) => {
    if( !req.headers.authorization ){
        console.log( req.headers )
        logger.warn('Request Validation Failed: Unable to locate authorization header.');
        res.sendStatus(401);
        return;
    }
    const token = req.headers.authorization.split(' ')[1];
    try{
        const decoded = validateAuthenticationToken(token, verificationKO);
        console.log( decoded );
        // const user = userStore.getUser(decoded.userId);
        // if( !user ){
        //     logger.warn(`Request Validation Failed: User '${decoded.userId}' does not exist.`);
        //     res.sendStatus(401);
        // }
        // req.user = user;
        next();
    }catch(err){
        logger.error(err);
        res.sendStatus(401);
        return;
    }

};



var verificationKO = requestVerificationKey().then( result => {
    verificationKO = result;
});

exports.handleRequestValidation = handleRequestValidation;