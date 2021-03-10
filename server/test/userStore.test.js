const assert = require('assert');
const crypto = require('crypto')

const userStore = require('../userStore');

console.log(module);

const getSHA256Hash = (input) => {
    const hash = crypto.createHash('sha256');
    hash.update(input);
    return hash.digest();
}

describe('userStore tests.', function() {
    before( function() {
        // Runs once before the first test in this block.
        userStore.createUser('test1','test123', ['test1','test2'] );
        userStore.createUser('test2','test456', ['test1','test2'] );
    });


    it('should allow you to create a new user', function() {
        const testUserId = 'test3';
        const testPass = 'test789';
        const testRoles = ['test1','test2'];

        userStore.createUser(testUserId,testPass,testRoles);
        const testUser = userStore.getUser('test3');

        assert( testUser.userId === testUserId, 'userId did not match expected value.');
        assert( testUser.roles === testRoles, 'userRoles did not match expected value.');

        const expectedHash = getSHA256Hash( testUser.pwSalt + testPass ).toString('hex');
        assert( testUser.pwHash === expectedHash, 'pwHash did not match expected value.' );
    });

    it('should allow you to retrieve a user', function() {
        assert( userStore.getUser('test1').userId === 'test1', 'failed to retrieve user: test1' );
        assert( userStore.getUser('test2').userId === 'test2', 'failed to retrieve user: test2' );
        assert( userStore.getUser('test3').userId === 'test3', 'failed to retrieve user: test3' );
    });

    it('should allow you to validate the correct password', function() {
        const testUserId = 'test4';
        const testPass = 'test789';
        const newUser = userStore.createUser( testUserId, testPass, ['test']);
        const expectedHash = getSHA256Hash( newUser.pwSalt + testPass ).toString('hex');
        assert( userStore.validatePassword( testUserId, expectedHash ), 'failed to validate password');
        assert( !userStore.validatePassword( testUserId, '1111111111' ), 'password validated with incorrect hash');
    });

    it('should fail validation with the incorrect hash', function() {
        const testUserId = 'test5';
        const testPass = 'test789';
        const newUser = userStore.createUser( testUserId, testPass, ['test']);
        assert( !userStore.validatePassword( testUserId, '1111111111' ), 'password validated with incorrect hash');
    });

    it('pending test');
});