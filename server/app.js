const express = require('express');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const { handleAuthentication, handleAuthenticationRefresh, handleRequestValidation, handleLogout, handleTRLRequest } = require('./securityManager.js');
const { getPublicResource, getProtectedResource } = require('./resourceController.js');

const app = express();
const port = 3000;

app.use(cors({origin: true}));      // Handle CORS preflight
app.use(cookieParser());            // Parse Cookies onto request obj
app.use(express.json());         // Parse JSON content onto request obj

app.get('/', (req,res) => {
    const responseObj = {
        message: 'Hey There!'
    }
    if( req.headers.authorization ){
        responseObj['auth'] = req.headers.authorization;
    }
    res.status(200).json( responseObj );
});

// Login State Management
app.post('/login', handleAuthentication );
app.post('/refresh', handleAuthenticationRefresh );
app.post('/logout', handleLogout );
app.get('/trl', handleRequestValidation, handleTRLRequest );

// Sample Resource Endpoints
app.get('/public',    getPublicResource );
app.get('/protected', handleRequestValidation, getProtectedResource );

//Start up express as configured above
app.listen( port, () => {
    console.log(`Secure JWT Demo listening at http://localhost:${port}`);
});
