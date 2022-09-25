require('dotenv').config()
const bodyParser = require('body-parser');
const express = require('express');
const mongoose = require('mongoose');
const passport = require('passport');
const passportLocalMongoose = require('passport-local-mongoose');
const session = require('express-session');
const GoogleStrategy = require('passport-google-oauth2').Strategy;
const findOrCreate = require('mongoose-findorcreate');


const app = express();

app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static(__dirname + '\public'));
app.use(session({
    secret: "this is a session secret",
    resave: false,
    saveUninitialized: false,
}));
app.use(passport.initialize());
app.use(passport.session());


mongoose.connect('mongodb+srv://faiz:'+process.env.MONGO_PASS+'@cluster0.wlh5r5u.mongodb.net/usersDB?appName=mongosh+1.5.4');
const userSchema = new mongoose.Schema({
    username: String,
    password: String,
    googleId: String,
    secret: String,
});
userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

const User = new mongoose.model('User', userSchema);

passport.use(User.createStrategy());
passport.serializeUser(function (user, done) {
    done(null, user.id);
});
passport.deserializeUser(function (id, done) {
    User.findById(id, function (err, user) {
        done(err, user);
    });
});

passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "https://submityoursecret.herokuapp.com/auth/google/secrets",
    userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo",
    passReqToCallback: true
},
    function (request, accessToken, refreshToken, profile, done) {
        //console.log(profile);
        User.findOrCreate({ googleId: profile.id }, function (err, user) {
            return done(err, user);
        });
    }
));

app.get('/', function (req,res) {
    res.render('home');
});

app.route('/auth/google').get(passport.authenticate('google', { scope: ['profile'] }), function (req, res) {
    console.log("Looks like you got authenticated");
})

app.route('/auth/google/secrets').get(
    passport.authenticate('google', {
        successRedirect: '/secrets',
        failureRedirect: '/login'
    }), function (req, res) {
        console.log('You should have been redirected to secrets route');
    }
);

app.get('/login', function (req, res) {
    res.render('login');
});

app.get('/register', function (req, res) {
    res.render('register');
});

app.get('/secrets', function (req, res) {

    User.find({ "secret": { $ne: null } }, function (err, users) {
        if (err) {
            console.log(err);
        }
        else {
            let isAuth = false;
            if (req.isAuthenticated()) {
                isAuth = true;
            }
            res.render('secrets', { usersWithSecrets: users, isAuth: isAuth });
        }
    });
});

app.get('/logout', function (req, res) {
    req.logOut(function (err) {
        if (err) {
            console.log(err);
            res.redirect('/secrets');
        }
        else {
            res.redirect('/');
        }
    });
});

app.get('/submit', function (req, res) {
    if (req.isAuthenticated()) {
        res.render('submit');
    }
    else {
        console.log('Not Authenticated');
        res.redirect('/login');
    }
});

app.post('/submit', function (req, res) {
    const secretText = req.body.secretText;
    User.findById(req.user.id, function (err, foundUser) {
        if (err) {
            console.log(err);
        }
        else {
            if (foundUser) {
                foundUser.secret = secretText;
                foundUser.save(function () {
                    res.redirect('/secrets');
                });
            }
        }
    });
})

app.post('/register', async function (req, res) {

    User.register(new User({ username: req.body.username }), req.body.password, function (err, user) {
        if (err) {
            console.log(err);
            res.redirect('/register');
        }
        else {
            req.login(user, function (e) {
                if (e) {
                    console.log(e);
                    res.redirect('/register');
                }
                else {
                    res.redirect('/secrets');
                }
            });
        }
    });
});

app.route('/login').post(passport.authenticate('local', { failureRedirect: '/login' }), function (req, res) {
    res.redirect('/secrets');
});


app.listen(process.env.PORT || 3000, function () {
    console.log('Succesfully running app on port');
});