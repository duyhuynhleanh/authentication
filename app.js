require('dotenv').config()
const mongoose = require('mongoose')
const express = require('express')
const bodyParser = require('body-parser')
const ejs = require('ejs')
const session = require('express-session')
const passport = require('passport')
const passportLocalMongoose = require('passport-local-mongoose')
const GoogleStrategy = require('passport-google-oauth2').Strategy
const findOrCreate = require('mongoose-findorcreate')

const app = express()

app.set('view engine', 'ejs')

app.use(bodyParser.urlencoded({ extended: true }))
app.use(express.static('public'))

app.use(
  session({
    secret: process.env.SECRET,
    resave: false,
    saveUninitialized: false,
  })
)

passport.serializeUser(function (user, done) {
  done(null, user.id)
})

passport.deserializeUser(function (id, done) {
  User.findById(id, function (err, user) {
    done(err, user)
  })
})

app.use(passport.initialize())
app.use(passport.session())

mongoose.connect(process.env.MONGO_URI)

const userSchema = new mongoose.Schema({
  email: String,
  password: String,
  googleId: String,
  secret: String,
})

userSchema.plugin(passportLocalMongoose)
userSchema.plugin(findOrCreate)

const User = mongoose.model('User', userSchema)

passport.use(User.createStrategy())

passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: 'http://localhost:3000/auth/google/secrets',
      passReqToCallback: true,
    },
    // function (request, accessToken, refreshToken, profile, done) {
    //   console.log(profile)
    //   User.findOrCreate({ googleId: profile.id }, function (err, user) {
    //     return done(err, user)
    //   })
    // }
    function (request, accessToken, refreshToken, profile, cb) {
      //console.log(profile);

      User.findOrCreate({ googleId: profile.id }, function (err, user) {
        return cb(err, user)
      })
    }
  )
)

app.get('/', (req, res) => {
  res.render('home')
})

app.get(
  '/auth/google',
  passport.authenticate('google', { scope: ['email', 'profile'] })
)

app.get(
  '/auth/google/secrets',
  passport.authenticate('google', {
    successRedirect: '/secrets',
    failureRedirect: '/login',
  })
)

app.get('/login', (req, res) => {
  res.render('login')
})

app.get('/register', (req, res) => {
  res.render('register')
})

app.get('/secrets', (req, res) => {
  User.find({ secret: { $ne: null } }, (err, foundUsers) => {
    if (err) {
      console.log(err)
    } else {
      if (foundUsers) {
        res.render('secrets', {
          usersWithSecrets: foundUsers,
        })
      }
    }
  })
})

app.get('/submit', (req, res) => {
  if (req.isAuthenticated()) {
    res.render('submit')
  } else {
    res.redirect('/login')
  }
})

app.post('/register', (req, res) => {
  User.register(
    { username: req.body.username },
    req.body.password,
    function (err, user) {
      if (err) {
        console.log(err)
        res.redirect('/register')
      } else {
        passport.authenticate('local')(req, res, function () {
          //console.log(req.user.username)
          res.redirect('/secrets')
        })
      }
    }
  )
})

app.post('/login', (req, res) => {
  const user = new User({
    username: req.body.username,
    password: req.body.password,
  })

  req.login(user, function (err) {
    if (err) {
      console.log(err)
    } else {
      passport.authenticate('local')(req, res, function () {
        res.redirect('/secrets')
      })
    }
  })
})

app.post('/submit', (req, res) => {
  const submittedSecret = req.body.secret
  //console.log(req.user.id)
  User.findById(req.user.id, (err, foundUser) => {
    if (err) {
      console.log(err)
    } else {
      if (foundUser) {
        foundUser.secret = submittedSecret
        foundUser.save(() => {
          res.redirect('/secrets')
        })
      }
    }
  })
})

app.get('/logout', (req, res) => {
  req.logout()
  res.redirect('/')
})

const PORT = process.env.PORT || 3000
app.listen(PORT, function () {
  console.log('Server started')
})
