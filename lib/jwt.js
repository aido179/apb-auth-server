var jwt = require('jsonwebtoken');

//set jwt secret + max_age from env variables if set.
const SECRET = process.env.JWT_SECRET || "somesecretphrase";
const MAX_AGE = process.env.JWT_MAX_AGE || 3600;


var verifyJWTToken = function(token, validationToken){
  return new Promise((resolve, reject) => {
    jwt.verify(token, SECRET+validationToken, (err, decodedToken) => {
      if (err || !decodedToken){
        return reject(err)
      }
      resolve(decodedToken)
    });
  });
}

var createJWToken = function(details){
  /**
  *  Details = {
  *     userID: ...,
  *     invalidationToken: ...
  *   }
  */

  //check details is an object
  if (typeof details !== 'object'){
    details = {}
  }
  //build the secret inlcuding the base secret and the user invalidation token
  //this allows server side invalidation
  builtSecret = SECRET+details.invalidationToken
  //sign the token.
  let token = jwt.sign({
     data: details
   }, builtSecret, {
      expiresIn: MAX_AGE,
      algorithm: 'HS256'
  })

  return token
}

module.exports = {
  verifyJWTToken:verifyJWTToken,
  createJWToken:createJWToken
}
