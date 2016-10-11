const Authentication = require('./controllers/authentication');
const passportService = require('./services/passport');
const passport = require('passport');

const requireAuth = passport.authenticate('jwt', { session: false });
const requireSignin = passport.authenticate('local', { session: false });

module.exports = function(app) {
  app.post('/signin', requireSignin, Authentication.signin); //if user not signed in Auth.signin won't be called, so user won't get token
  app.post('/signup', Authentication.signup);
}