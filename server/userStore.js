const { logger } = require('./logManager');
const crypto = require('crypto')

const users = {};

const calculatePasswordHash = (input) => {
    const salt = crypto.randomBytes(32).toString('hex');
    const hash = crypto.createHash('sha256');
    hash.update( salt + input );
    return {
        pwHash: hash.digest().toString('hex'),
        pwSalt: salt
    }
}

const createUser = (userId,password,roles) => {
    const pwResult = calculatePasswordHash(password);
    const newUser = {
        userId: userId,
        roles: roles,
        ...pwResult
    }
    logger.debug(`User Created: ${newUser.userId},${newUser.pwHash},${newUser.pwSalt}`);
    users[userId] = newUser;
    return newUser;
};

const getUser = (userId) => {
    return users[userId];
};

exports.createUser = createUser;
exports.getUser = getUser;

