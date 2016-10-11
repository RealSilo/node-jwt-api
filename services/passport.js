const passport = require('passport');
const User = require('../models/user');
const config = require('../config');
const JwtStrategy = require('passport-jwt').Strategy;
const ExtractJwt = require('passport-jwt').ExtractJwt;
const LocalStrategy = require('passport-local');

//create local strategy
const localOptions = { usernameField: 'email' };
const localLogin = new LocalStrategy(localOptions, function(email, password, done) {

  User.findOne({ email: email }, function(err, user) {
    //verify username and pw and call done with user
    if (err) { return done(err); }

    //call done without user if user is not correct
    if (!user) { return done(null, false); }

    //call done with user if the correct pw is correct
    user.comparePassword(password, function(err, isMatch) {
      if (err) { return done(err); }
      if (!isMatch) { return done(null, false); }

      return done(null, user);
    });
  });  
});

//setup options for JWT strategy
const jwtOptions = {
  jwtFromRequest: ExtractJwt.fromHeader('authorization'),
  secretOrKey: config.secret
};

//create JWT strategy
//payload is userid+timestamp from tokenForUser
const jwtLogin = new JwtStrategy(jwtOptions, function(payload, data) {
  //see if the userID in the payload exists in db
  User.findById(payload.sub, function(err, user) {
    if (err) { 
      //if search goes wrong
      return done(err, false);
    }

    if (user) {
      //if there is user in db, call "done" with that
      done(null, user);
    } else {
      //otherwise, call "done without a user object" (search went thru but no user in db)
      done(null, false)
    }
  });
});

passport.use(jwtLogin);
passport.use(localLogin);