const { logger } = require('./logManager.js');
const https = require('https');
const fs = require('fs');
const express = require('express');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const { handleAuthentication, handleAuthenticationRefresh, handleRequestValidation, handleLogout, handleTRLRequest } = require('./securityManager.js');
const { getPublicResource, getProtectedResource } = require('./resourceController.js');
const { nextTick } = require('process');

const app = express();
const port = 3000;

// Handle CORS preflight
app.use(cors({
    origin: "http://localhost:8080",
    credentials: true,
}));

app.use(cookieParser());         // Parse Cookies onto request obj
app.use(express.json());         // Parse JSON content onto request obj

const httpLogger = (request,response,next) => {
    const requestStart = Date.now();
    const { rawHeaders, httpVersion, method, socket, url, body, cookies } = request;
    const { remoteAddress, remoteFamily } = socket;
    next();
    const { statusCode, statusMessage } = response;
    const headers = response.getHeaders();

    logger.info(
      JSON.stringify({
        timestamp: Date.now(),
        processingTime: Date.now() - requestStart,
        rawHeaders,
        cookies,
        //body,
        //errorMessage,
        //httpVersion,
        method,
        remoteAddress,
        remoteFamily,
        url,
        response: {
          statusCode,
          statusMessage,
          headers
        }
      })
    );
}


// Login State Management
app.post('/login', httpLogger, handleAuthentication );
app.post('/refresh', httpLogger, handleAuthenticationRefresh );
app.post('/logout', handleLogout );
app.get('/trl', handleRequestValidation, handleTRLRequest );

// Sample Resource Endpoints
app.get('/', getPublicResource );
app.get('/public', getPublicResource );
app.get('/protected', httpLogger, handleRequestValidation, getProtectedResource );



//Start up express as configured above
const certificates = {
    key:  fs.readFileSync('certs/server.key'),
    cert: fs.readFileSync('certs/server.cert')
}
https.createServer(certificates,app).listen(port, () => {
     logger.info('******************************************************');
     logger.info(`Secure JWT Demo listening at https://localhost:${port}`);
     logger.info('******************************************************');
});