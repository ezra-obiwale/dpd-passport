// greybox testing
var expect = require('chai').expect,
    app = require('../testapp/test-server'),
    api = require('supertest')(app),

    // npm will copy the current passport version on test
    passport = require('../testapp/node_modules/dpd-passport/index'),

    testuser = {
        username: 'test@user.net',
        password: 'testing'
    },
    socialUser = {
        id: '1234567890',
        username: 'Test2',
        displayName: 'Before Name Change',
        name: {
            familyName: 'Tester',
            givenName: 'Test',
            middleName: undefined
        },
        gender: 'male',
        profileUrl: 'https://www.simpletechs.net',
        emails: [{
            value: 'test@example.com' // will not send real email
        }],
        provider: 'overrideme'
    };

var userStore = app.createStore('users');

// fake social auth callback, i.e. pretend it always succeeds.
var oldInit = passport.prototype.initPassport,
    newInit = function() {
        var ret = oldInit.apply(this, arguments);

        var pp = this.passport,
            oldAuth = this.passport.authenticate;
        this.passport.authenticate = function(strategy, options, callback) {
            if(['facebook', 'twitter', 'google'].indexOf(strategy) === -1) {
                return oldAuth.apply(this, arguments);
            } else {
                var prototype = pp._strategy(strategy);
                return function(req, res, done) {
                    prototype._verify.call(prototype, '', '', socialUser, callback);
                };
            }
        };

        return ret;
    };

before(function(done){
    this.timeout(10000);

    process.server.on('listening', function() {
        // delete existing user
        userStore.remove({username: testuser.username}, function() {
            // setup a testuser to use with the next requests
            api.post('/users')
                .send(testuser)
                .expect(200)
                .end(function(error, res) {
                    expect(error).to.equal(null);

                    testuser.id = res.body.id;

                    api.post('/users/login')
                        .send({username: testuser.username, password: testuser.password})
                        .expect(200)
                        .end(function(error, res) {
                            expect(error).to.equal(null);

                            testuser.sid = res.body.id;

                            done();
                        });
                });
        });
    }); // wait for the server to startup
});

function validateUser(sid, equalUser, done) {
    api.get('/users/me')
            .set('Cookie', 'sid='+sid)
            .expect(200)
            .end(function(error, res) {
                var user = res.body;

                expect(user)
                    .to.have.property('id');
                expect(user)
                    .to.not.have.property('password');

                if(!user.socialAccount) {
                    expect(user)
                        .to.have.property('username')
                            .that.is.equal(equalUser.username);
                }

                if(equalUser.displayName) {
                    expect(user)
                        .to.have.property('name')
                            .that.is.equal(equalUser.displayName);
                }

                equalUser.sid = sid;
                equalUser._id = res.body.id;
                done();
            });

}

describe('deployd errors', function() {
    //TODO check if dpd-passport allow multiple logouts
    it('should logout cleanly', function(done) {
        api.post('/users/login')
            .send({username: testuser.username, password: testuser.password})
            .expect(200)
            .end(function(err, res) {
                expect(res.body).to.have.property('id');

                var sessionId = res.body.id;
                api.post('/users/logout')
                    .set('Cookie', 'sid='+sessionId)
                    .expect(200)
                    .end(function(err, res) {
                        expect(res.header)
                            .to.have.property('set-cookie')
                                .that.is.instanceof(Array)
                                .and.has.length(1);

                        api.post('/users/logout')
                            .set('Cookie', 'sid='+sessionId)
                            .expect(200, done); // we expect an error here, the user cannot logout twice

                    });
            });
    });

    it('should not be allowed to logout twice', function(done) {
        api.post('/users/login')
            .send({username: testuser.username, password: testuser.password})
            .expect(200)
            .end(function(err, res) {
                expect(res.body).to.have.property('id');

                var sessionId = res.body.id;

                api.get('/users/me')
                    .set('Cookie', 'sid='+sessionId)
                    .expect(200, function(err) {
                        if(err) done(err);

                        api.post('/users/logout')
                            .set('Cookie', 'sid='+sessionId)
                            .expect(200)
                            .end(function(err, res) {
                                if(err) done(err);
                                api.get('/users/me')
                                    .set('Cookie', 'sid='+sessionId)
                                    .expect(204, function(err) { // 204 means we're logged out
                                        if(err) done(err);

                                        api.post('/users/logout')
                                            .set('Cookie', 'sid='+sessionId)
                                            .expect(200, done); // we would expect an error here, because the user cannot logout twice
                                                                // but that would tell somebody the session was active, so 200 is probably okay
                                    });
                            });
                    });
            });
    });
});

describe('Authentification', function(){
    it('should allow our testuser to login', function(done){
        api.post('/users/login')
            .send({username: testuser.username, password: testuser.password})
            .expect(200, done);
    });
    it('should not allow a different testuser to login', function(done){
        api.post('/users/login')
            .send({username: testuser.username + '.co.uk', password: 'not valid'})
            .expect(401, done);
    });
});

describe('Read-Only', function() {
    it('should return a user with only his own collection', function(done) {
        validateUser(testuser.sid, testuser, done);
    });
});



function verifySocialLogin(call, done) {
    call.expect(200)
        .end(function(error, res) {
            if(error) throw error;
            expect(res.body)
                .to.have.property('uid');

            expect(res.body)
                .to.have.property('id');

            expect(error)
                .to.equal(null);

            // re-enable oauth flow after this test
            passport.prototype.initPassport = oldInit;

            validateUser(res.body.id, socialUser, done);
        });
}

describe('dpd-passport: login', function(){
    this.timeout(10000); // twitter tends to take ~1-3s

    it('should allow our testuser to login', function(done){
        api.post('/auth/login')
            .send({username: testuser.username, password: testuser.password})
            .expect(200, done);
    });

    it('should not allow a different testuser to login', function(done){
        api.post('/auth/login')
            .send({username: testuser.username + '.co.uk', password: 'not valid'})
            .expect(401, done);
    });

    it('should not allow a get on login', function(done){
        api.get('/auth/login')
            .expect(401, done);
    });

    it('should not allow a get on unknown login strategy', function(done){
        api.get('/auth/fakelogin')
            .expect(401, done);
    });

    it('should not allow a post on unknown login strategy', function(done){
        api.post('/auth/fakelogin')
            .expect(401, done);
    });

    [{
        name: 'facebook',
        redirectURL: 'https://www.facebook.com/dialog/oauth?response_type=code&redirect_uri='
    },{
        name: 'twitter',
        redirectURL: 'https://api.twitter.com/oauth/authenticate?oauth_token='
    },{
        name: 'google',
        redirectURL: 'https://accounts.google.com/o/oauth2/auth?response_type=code&redirect_uri='
    }].forEach(function(provider) {
        xit('should redirect a ' + provider.name + ' request to ' + provider.redirectURL, function(done) {
            api.get('/auth/' + provider.name)
                .expect(302) // expect redirect
                .end(function(error, res) {
                    if(error) done(error);

                    expect(res.header)
                        .to.have.property('location')
                        .to.satisfy(function(str) { return str.indexOf(provider.redirectURL) === 0; }, 'expected ' + provider.name + ' login url');

                    done(error);
                });
        });

        it('should successfully register a new ' + provider.name + ' user', function(done){
            // bypass oauth flow for this test only
            passport.prototype.initPassport = newInit;
            socialUser.provider = provider.name;

            // delete existing user
            userStore.remove({socialAccountId: socialUser.id}, function() {
                verifySocialLogin(api.get('/auth/' + provider.name), done);
            });
        });

        it('should successfully login an existing ' + provider.name + ' user', function(done){
            // bypass oauth flow for this test only
            passport.prototype.initPassport = newInit;
            socialUser.provider = provider.name;

            verifySocialLogin(api.get('/auth/' + provider.name), done);
        });
    });
});

describe('dpd-passport: updating the user', function() {
    this.timeout(10000);

    it('should update the users name', function(done) {

        var newName = 'After Name Change';

        api.put('/users/' + socialUser._id)
            .set('Cookie', 'sid='+socialUser.sid)
            .send({'name': newName})
            .expect(200)
            .end(function(error, res) {
                if(error) throw error;
                api.post('/users/logout')
                    .send()
                    .expect(200)
                    .end(function(error, res) {
                        if(error) throw error;
                        // relogin with twitter user

                        passport.prototype.initPassport = newInit;
                        socialUser.provider = 'twitter';

                        api.get('/auth/twitter')
                            .expect(200)
                            .end(function(error, res) {
                                if(error) throw error;
                                expect(res.body)
                                    .to.have.property('id')
                                    .not.be.equal(socialUser.sid);

                                // re-enable oauth flow after this test
                                passport.prototype.initPassport = oldInit;

                                socialUser.displayName = newName;
                                validateUser(res.body.id, socialUser, done);
                            });
                    });
            });
    });
});