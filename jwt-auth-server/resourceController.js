const getPublicResource = async(req, res) => {
    const responseObj = {
        message: `fetched a public resource from auth-server: ${new Date().toISOString()}`
    }
    res.status(200).json( responseObj );
}

const getProtectedResource = async(req,res) => {
    const responseObj = {
        message: `fetched a protected resource from auth-server: ${new Date().toISOString()}`
    }
    res.status(200).json( responseObj );
}

exports.getPublicResource = getPublicResource;
exports.getProtectedResource = getProtectedResource;

