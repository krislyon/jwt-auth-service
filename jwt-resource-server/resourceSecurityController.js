const axios = require('axios');
const { logger } = require('./logManager');
const crypto = require('crypto');
const https = require('https');

logger.warn("*****************************************************************************");
logger.warn("Demo implmentation requiring further hardening.  Do not deploy to production.");
logger.warn("- Update self-signed SSL Certificates");
logger.warn("- Update CORS Configuration");
logger.warn("- Support multiple verification keys");
logger.warn("*****************************************************************************");

// Load token signing keys
const requestVerificationKey = async() => {

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
    axios.get('/tokenverificationkey', options )
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

const handleRequestValidation = async(req,res,next) => {
    if( !req.headers.authorization ){
        logger.warn('Request Validation Failed: Unable to locate authorization header.');
        res.sendStatus(401);
        return;
    }
    const token = req.headers.authorization.split(' ')[1];
    try{
        const decoded = validateAuthenticationToken(token, verificationKO);
        // const user = userStore.getUser(decoded.userId);
        // if( !user ){
        //     logger.warn(`Request Validation Failed: User '${decoded.userId}' does not exist.`);
        //     res.sendStatus(401);
        // }
        // req.user = user;
        next();
    }catch(err){
        res.sendStatus(401);
        return;
    }

};

const verificationKO = requestVerificationKey();

exports.handleRequestValidation = handleRequestValidation;