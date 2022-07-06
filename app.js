require("dotenv").config();
const express = require('express');
const bodyParser = require('body-parser');
const mongoose = require('mongoose');
const session = require("express-session");
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const GitHubStrategy = require('passport-github2').Strategy;
const findOrCreate = require("mongoose-findorcreate");
// also install passport-local 

// const encrypt = require("mongoose-encryption");
// const md5 = require("md5");
// const bcrypt = require('bcrypt');
// const saltRounds = 10;

const app = express();

app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public"));

app.use(session({
    secret: process.env.SECRET,
    resave: false,
    saveUninitialized: false,
}));

app.use(passport.initialize());
app.use(passport.session());

mongoose.connect("mongodb://localhost:27017/userDB", {useNewUrlParser: true});

const userSchema = mongoose.Schema({
    email: String,
    password: String,
    googleId: String,
    githubId: String,
    secret: String
});

userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

// userSchema.plugin(encrypt, {secret: process.env.SECRET, encryptedFields: ["password"]});

const User = new mongoose.model("User", userSchema);
passport.use(User.createStrategy());

// passport.serializeUser(User.serializeUser());
// passport.deserializeUser(User.deserializeUser());

passport.serializeUser(function(user, cb) {
    process.nextTick(function() {
      cb(null, { id: user.id, username: user.username });
    });
  });
  
passport.deserializeUser(function(user, cb) {
    process.nextTick(function() {
      return cb(null, user);
    });
});

// Using the Google strategy for Authentication
passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID, //gotten from the google console
    clientSecret: process.env.GOOGLE_CLIENT_SECRET, //gotten from the google console
    callbackURL: "http://localhost:3000/auth/google/secrets"
  },
  function(accessToken, refreshToken, profile, cb) {                     
    User.findOrCreate({ googleId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));

passport.use(new GitHubStrategy({
    clientID: process.env.GITHUB_CLIENT_ID,
    clientSecret: process.env.GITHUB_CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/github/secrets"
  },
  function(accessToken, refreshToken, profile, done) {
    console.log(profile);
    User.findOrCreate({ githubId: profile.id }, function (err, user) {
      return done(err, user);
    });
  }
));

app.get('/', (req, res) =>{
    res.render("home");
});

app.get('/auth/google',
  passport.authenticate('google', { scope: ['profile'] }));

app.get('/auth/google/secrets', 
// where google redirects to after authentication
  passport.authenticate('google', { failureRedirect: '/login' }),
  function(req, res) {
    // Successful authentication, redirect to secrets page.
    res.redirect('/secrets');
});

app.get('/auth/github',
  passport.authenticate('github', { scope: [ 'user:email' ] }));

app.get('/auth/github/secrets', 
  passport.authenticate('github', { failureRedirect: '/login' }),
  function(req, res) {
    // Successful authentication, redirect home.
    res.redirect('/secrets');
});

app.get('/login', (req, res) =>{
    res.render("login");
});

app.get('/register', (req, res) =>{
    res.render("register");
});

app.get("/secrets", (req, res) =>{
    User.find({secret: {$ne: null}}, (err, foundUsers) =>{
        if (err) {
            console.log(err);
        }else{
            if (foundUsers){
                res.render("secrets", {usersWithSecrets: foundUsers});
            }
        }
    })
});

app.get("/logout", (req, res) =>{
    // log the user out easily
    req.logout(function(err){
        if(err){console.log(err);}
        res.redirect("/");
    });
});

app.get("/submit", (req, res) =>{
    // check if user is authenticated
    if (req.isAuthenticated()) {
        res.render("submit");
    }else{
        // send back to the login page
        res.redirect("/login");
    }
})

app.post("/submit", (req, res) =>{
    const userSecret = req.body.secret;
    // req.user allows you to know who the current user is or who is currently logged in

    User.findById(req.user.id, function(err, foundUser){
        if (err) {
            console.log(err);
        }else{
            if (foundUser){
                foundUser.secret = userSecret;
                foundUser.save(function(err){
                    if (err) {
                        console.log(err);
                    }
                    res.redirect("/secrets");
                });
            }
            
        }
        
    });
});
app.post("/register", function(req, res){
    // local registration using the passport-local package
    // get the username and hash the password
    User.register({username: req.body.username}, req.body.password, function(err, user){
        if(err){
            console.log(err);
            res.redirect("/register");
        }else{
            // create session using passport and redirect t0 secrets route
            passport.authenticate("local")(req, res, function(){
                res.redirect("/secrets")
            });
        }
    });
});

app.post("/login", function(req, res){
    // take in the user's details
   const user = new User({
    username: req.body.username,
    password: req.body.password
   });
//    log the user in
   req.login(user, function(err){
    if (err) {
        console.log(err);
    }else{
        // create login session using passport
        passport.authenticate("local")(req, res, function(){
            res.redirect("/secrets");
        });
    }
   });
});

app.listen(3000, ()=>{
    console.log('listening on port 3000');
});
