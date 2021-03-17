const getPublicResource = async(req, res) => {
    const responseObj = {
        message: `fetched a public resource: ${new Date().toISOString()}`
    }
    res.status(200).json( responseObj );
}

const getProtectedResource = async(req,res) => {
    const responseObj = {
        message: `fetched a protected resource: ${new Date().toISOString()}`
    }
    res.status(200).json( responseObj );
}

exports.getPublicResource = getPublicResource;
exports.getProtectedResource = getProtectedResource;

