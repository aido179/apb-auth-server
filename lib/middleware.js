const verifyJWTToken = require('./jwt.js').verifyJWTToken;
const createJWToken = require('./jwt.js').createJWToken;
/*
*
* Middleware for authorizing the user and verifying their roles.
* These middleware functions WILL NOT work for multipart or streaming requests.
* Alternatively, use the functions in endware.js
*
*/

/*
* verifyVerification - check the user has been verified
* (TODO: refactor...what a terrible function signature/name)
*/
var verifyVerification = function (req, res, next){
  req.app.locals.userController.getUser(req.validation.userID)
  .then(function(user){
    if(user.isVerified === true){
      next();
    }else{
      res.status(405)
        .json({message: "Ignoring Call: User is not verified."});
    }
  })
}

/*
* verifyRole - check the user has the given role
*/
var verifyRole = function(role){
  return function(req, res, next){
    //check the user login (JWT token) has been verified
    if(req.validation.userID === undefined){
      res.status(401)
        .json({message: "Authentication failed. (did you forget to call use the verifyLogin middleware first?)"});
    }
    //check the user role matches the provided role
    req.app.locals.userController.getUser(req.validation.userID)
    .then(function(user){
      if(user.role === role){
        next();
      }else{
        res.status(401)
          .json({message: "Role mismatch."});
      }
    })
    .catch(function(err){
      res.status(401)
        .json({
          status:"error",
          message: "Error getting user to verify role.",
          error: err
        });
    });
  }
}

var verifyRoles = function(roles){
  return function(req, res, next){
    //check the user login (JWT token) has been verified
    if(req.validation.userID === undefined){
      res.status(401)
        .json({message: "Authentication failed. (did you forget to call use the verifyLogin middleware first?)"});
    }
    //check the user role matches the provided role
    req.app.locals.userController.getUser(req.validation.userID)
    .then(function(user){
      if (roles.indexOf(user.role) > -1){
        next();
      } else{
        res.status(401)
          .json({message: "Role mismatch."});
      }
    })
    .catch(function(err){
      res.status(401)
        .json({
          status:"error",
          message: "Error getting user to verify role.",
          error: err
        });
    });
  }
}

/*
* verifyLogin - check the JWT token is valid - ie, the user is logged in.
*/
var verifyLogin = function (req, res, next){
  let token = (req.method === 'POST' || req.method === 'PUT') ? req.body.token : req.query.token
  req.app.locals.userController.getValidationToken(token)
  .then(function(validationToken){
    verifyJWTToken(token, validationToken)
    .then((decodedToken) => {
      //add the userID to the request so other middleware / routes can use it.
      req.validation = decodedToken.data
      next();
    })
    .catch((err) => {
      res.status(401)
        .json({message: "Invalid auth token provided."});
    });
  })
  .catch((err) => {
    res.status(401)
      .json({
        status:"error",
        message: "JWT validator not found.",
        error: err
      });
  });

}

/*
* verifyDataIntegrationService - check the JWT token is valid - ie, the user is logged in.
*/
var verifyDataIntegrationService = function (req, res, next){
  let token = (req.method === 'POST' || req.method === 'PUT') ? req.body.token : req.query.token
  req.app.locals.dataIntegrationServiceController.getValidationToken(token)
  .then(function(validationToken){
    verifyJWTToken(token, validationToken)
    .then((decodedToken) => {
      //add the userID to the request so other middleware / routes can use it.
      req.validation = decodedToken.data
      next();
    })
    .catch((err) => {
      res.status(401)
        .json({message: "Invalid auth token provided."});
    });
  })
  .catch((err) => {
    res.status(401)
      .json({
        status:"error",
        message: "JWT validator not found.",
        error: err
      });
  });

}

var login = function(userID, invalidationToken){
  return createJWToken({
    userID: userID,
    invalidationToken: invalidationToken
  })
}

module.exports = {
  verifyLogin:verifyLogin,
  verifyRole:verifyRole,
  verifyRoles: verifyRoles,
  verifyVerification:verifyVerification,
  login:login,
  verifyDataIntegrationService:verifyDataIntegrationService
}
