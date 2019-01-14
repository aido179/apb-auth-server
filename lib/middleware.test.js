var middleware = require('./middleware');
var assert = require('assert');
describe('Authentication Middleware', function() {

  describe('#verifyVerification()', function() {
    it('should send http 405 if the user is not verified.', function(done) {
      /*
      * Very messy, but we have to mock the req, res, next parameters for each
      * middleware. These are usually provided by express itself.
      */
      var req = {
        'app': {
          'locals': {
            'userController': {
              'getUser': function(userid){
                return Promise.resolve({
                  isVerified: false  // hard coding the user to not be verified.
                })
              }
            }
          }
        },
        'validation': {
          'userID': "something"
        }
      }
      var res = {
        'status': function(code){
          assert.equal(code, 405)
          done()
          return {
            'json': function(x){return /*does nothing*/}
          }
        }
      }
      var next = function(){
        throw new Error("Should not call next()");
      }
      middleware.verifyVerification(req, res, next)
    })
    it('should call next the user is verified.', function(done) {
      var req = {
        'app': {
          'locals': {
            'userController': {
              'getUser': function(userid){
                return Promise.resolve({
                  isVerified: true // hard coding the user to be verified.
                })
              }
            }
          }
        },
        'validation': {
          'userID': "something"
        }
      }
      var res = {
        'status': function(code){
          throw new Error("Should not call status()");
        }
      }
      var next = function(){
        done()
      }
      middleware.verifyVerification(req, res, next)
    })
  })
  describe('#verifyRole()', function() {
    it('should send http 401 if the JWT token is not verified.', function(done) {
      var req = {
        'validation': {
          // userID not included here specifically to force a failure
        }
      }
      var res = {
        'status': function(code){
          assert.equal(code, 401)
          done()
          return {
            'json': function(x){return /*does nothing*/}
          }
        }
      }
      middleware.verifyRole('HotChickenRole')(req, res, null)
    })
    it('should send http 401 if the roles do not match.', function(done) {
      var req = {
        'app': {
          'locals': {
            'userController': {
              'getUser': function(userid){
                return Promise.resolve({
                  role: 'SpringRole'  // hard coding the user role.
                })
              }
            }
          }
        },
        'validation': {
          'userID': "something"
        }
      }
      var res = {
        'status': function(code){
          assert.equal(code, 401)
          done()
          return {
            'json': function(x){return /*does nothing*/}
          }
        }
      }
      middleware.verifyRole('HotChickenRole')(req, res, null)
    })
    it('should send http 401 if the user is not found.', function(done) {
      var req = {
        'app': {
          'locals': {
            'userController': {
              'getUser': function(userid){
                return Promise.reject("Test error message")
              }
            }
          }
        },
        'validation': {
          'userID': "something"
        }
      }
      var res = {
        'status': function(code){
          assert.equal(code, 401)
          done()
          return {
            'json': function(x){return /*does nothing*/}
          }
        }
      }
      middleware.verifyRole('HotChickenRole')(req, res, null)
    })
    it('should call next() if the roles match.', function(done) {
      var req = {
        'app': {
          'locals': {
            'userController': {
              'getUser': function(userid){
                return Promise.resolve({
                  role: 'HotChickenRole'  // hard coding the user role.
                })
              }
            }
          }
        },
        'validation': {
          'userID': "something"
        }
      }
      var res = {
        'status': function(code){
          throw new Error("Should not call status()");
        }
      }
      var next = function(){
        done()
      }
      middleware.verifyRole('HotChickenRole')(req, res, next)
    })
  })

  describe('#verifyRoles()', function() {
    it('should send http 401 if the JWT token is not verified.', function(done) {
      var req = {
        'validation': {
          // userID not included here specifically to force a failure
        }
      }
      var res = {
        'status': function(code){
          assert.equal(code, 401)
          done()
          return {
            'json': function(x){return /*does nothing*/}
          }
        }
      }
      middleware.verifyRoles('HotChickenRole')(req, res, null)
    })
    it('should send http 401 if the roles do not match.', function(done) {
      var req = {
        'app': {
          'locals': {
            'userController': {
              'getUser': function(userid){
                return Promise.resolve({
                  role: 'SpringRole'  // hard coding the user role.
                })
              }
            }
          }
        },
        'validation': {
          'userID': "something"
        }
      }
      var res = {
        'status': function(code){
          assert.equal(code, 401)
          done()
          return {
            'json': function(x){return /*does nothing*/}
          }
        }
      }
      middleware.verifyRoles('HotChickenRole')(req, res, null)
    })
    it('should send http 401 if the user is not found.', function(done) {
      var req = {
        'app': {
          'locals': {
            'userController': {
              'getUser': function(userid){
                return Promise.reject("Test error message")
              }
            }
          }
        },
        'validation': {
          'userID': "something"
        }
      }
      var res = {
        'status': function(code){
          assert.equal(code, 401)
          done()
          return {
            'json': function(x){return /*does nothing*/}
          }
        }
      }
      middleware.verifyRoles('HotChickenRole')(req, res, null)
    })
    it('should call next() if the roles match.', function(done) {
      var req = {
        'app': {
          'locals': {
            'userController': {
              'getUser': function(userid){
                return Promise.resolve({
                  role: 'HotChickenRole'  // hard coding the user role.
                })
              }
            }
          }
        },
        'validation': {
          'userID': "something"
        }
      }
      var res = {
        'status': function(code){
          throw new Error("Should not call status()");
        }
      }
      var next = function(){
        done()
      }
      middleware.verifyRoles('HotChickenRole')(req, res, next)
    })
  })
  /*
  TODO: implement this
  describe('#verifyLogin()', function() {
    it('should reject an empty gtest.', function(done) {
    })
  })
  */
})
