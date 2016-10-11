const mongoose = require('mongoose');
const Schema = mongoose.Schema;
const bcrypt = require('bcrypt-nodejs');

//define our model
const userSchema = new Schema({
  email: { type: String, unique: true, lowercase: true },
  password: String
});

userSchema.pre('save', function(next) {
  //getting access to the user model
  const user = this; //user instance

  //generating a salt then run callback
  bcrypt.genSalt(10, function(err, salt) {
    if (err) { return next(err); }

    //hash (encrypt) pw using the generated salt
    bcrypt.hash(user.password, salt, null, function(err, hash) { 
      if (err) { return next(err); }

      //overwrite plain text pw w/ encrypted pw
      user.password = hash;
      next();
    });
  });
});

userSchema.methods.comparePassword = function(candidatePassword,callback) {
  bcrypt.compare(candidatePassword, this.password, function(err, isMatch) {
    if (err) { return callback(err); }

    callback(null, isMatch);
  });
}

//create model class
const modelClass = mongoose.model('user', userSchema);

//export the model;
module.exports = modelClass;