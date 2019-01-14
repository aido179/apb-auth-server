const verifyJWTToken = require('./jwt.js').verifyJWTToken;
const createJWToken = require('./jwt.js').createJWToken;
/*
*
* "Endware" for authorizing the user and verifying their roles.
* These functions are alternatives to middleware for multipart or streaming requests.
*
* 1. body-parser does not handle streaming requests - so we use busboy instead.
* 2. busboy (due to the nature of streaming requests) doesn't "fit" in middleware.
*    because the request is streaming, we can't pass the full request through
*    middleware until it is complete - and would beed to cache the whole request...
*    Not particularly efficient.
*
* If you are not using busboy / streaming requests, use the functions in middleware.js
*
*/

/*
* verifyLogin - check the JWT token is valid - ie, the user is logged in.
*/
var verifyLogin = function (req, res, token){
  return new Promise(function(resolve, reject){
    req.app.locals.userController.getValidationToken(token)
      .then(function(validationToken){
        verifyJWTToken(token, validationToken)
          .then((decodedToken) => {
            // add the userID to the request / return it
            req.validation = decodedToken.data
            resolve(decodedToken.data)
          })
          .catch((err) => {
            reject(err)
          });
      })
      .catch((err) => {
        reject(err)
     });
 })
}

/*
* verifyRole - check the user has the given role
*/
var verifyRole = function(req, res, role){
  return new Promise(function(resolve, reject){
    //check the user login (JWT token) has been verified
    if(req.validation.userID === undefined){
      reject({message: "Authentication failed. (did you forget to call use the verifyLogin middleware first?)"})
    }
    //check the user role matches the provided role
    req.app.locals.userController.getUser(req.validation.userID)
    .then(function(user){
      if(user.role === role){
        resolve({
          status:"success",
          message: "User role verified.",
        });
      }else{
        reject({message: "Role mismatch."});
      }
    })
    .catch(function(err){
      reject({
        status:"error",
        message: "Error getting user to verify role.",
        error: err
      });
    });
  });
}

module.exports = {
  verifyLogin:verifyLogin,
  verifyRole:verifyRole,
  //verifyVerification:verifyVerification,
  //login:login
}
