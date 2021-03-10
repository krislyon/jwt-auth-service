const getPublicResource = async(req, res) => {
    const responseObj = {
        message: 'public resource'
    }
    if( req.headers.authorization ){
        responseObj['auth'] = req.headers.authorization;
    }
    res.status(200).json( responseObj );
}

const getProtectedResource = async(req,res) => {
    const responseObj = {
        message: 'protected resource'
    }
    res.status(200).json( responseObj );
}

exports.getPublicResource = getPublicResource;
exports.getProtectedResource = getProtectedResource;

