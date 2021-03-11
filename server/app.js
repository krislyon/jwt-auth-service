const { logger } = require('./logManager.js');
const https = require('https');
const fs = require('fs');
const express = require('express');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const { handleAuthentication, handleAuthenticationRefresh, handleRequestValidation, handleLogout, handleTRLRequest } = require('./securityManager.js');
const { getPublicResource, getProtectedResource } = require('./resourceController.js');

const app = express();
const port = 3000;

app.use(cors({origin: true}));   // Handle CORS preflight
app.use(cookieParser());         // Parse Cookies onto request obj
app.use(express.json());         // Parse JSON content onto request obj

// Login State Management
app.post('/login', handleAuthentication );
app.post('/refresh', handleAuthenticationRefresh );
app.post('/logout', handleLogout );
app.get('/trl', handleRequestValidation, handleTRLRequest );

// Sample Resource Endpoints
app.get('/', getPublicResource );
app.get('/public', getPublicResource );
app.get('/protected', handleRequestValidation, getProtectedResource );

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