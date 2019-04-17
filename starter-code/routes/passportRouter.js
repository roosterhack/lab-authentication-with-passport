const express = require("express");
const passportRouter = express.Router();
const User = require("../models/user");
const bcrypt = require("bcrypt");
const passport = require("passport");

passportRouter.get("/signup", (req, res, next) => {
  res.render("passport/signup");
});

passportRouter.get("/login", (req, res, next) => {
  res.render("passport/login", {
    errorMessage: req.flash("error")
  });
});

passportRouter.get("/logout", (req, res, next) => {
  req.logout();
  res.redirect("/");
});

//login logic
passportRouter.post(
  "/login",
  passport.authenticate("local", {
    successRedirect: "/",
    failureRedirect: "passport/login",
    failureFlash: true,
    passReqToCallback: true
  })
);
const ensureLogin = require("connect-ensure-login");

passportRouter.get("/secret", (req, res, next) => {
  if (req.isAuthenticated()) {
    res.render("passport/secret");
  } else {
    res.render("error", { errorMessage: "This is a protected route" });
  }
});

//Signup logic
passportRouter.post("/signup", (req, res, next) => {
  const { username, password } = req.body;
  const salt = bcrypt.genSaltSync();
  const hashPassword = bcrypt.hashSync(password, salt);

  if (username === "" || password === "") {
    res.render("", {
      errorMessage: "You need a username and a password to register"
    });
    return;
  }
  if (password.length < 6) {
    res.render("passport/signup", {
      errorMessage: "Your password needs 6 or more characters"
    });
    return;
  }

  User.findOne({ username })
    .then(user => {
      if (user) {
        res.render("passport/signup", {
          errorMessage: "There is already a registered user with this username"
        });
        return;
      }
      User.create({ username, password: hashPassword })
        .then(() => {
          res.redirect("/");
        })
        .catch(err => {
          console.error("Error while registering new user", err);
          next();
        });
    })
    .catch(err => {
      console.error("Error while looking for user", err);
    });
});

passportRouter.get("/private-page", ensureLogin.ensureLoggedIn(), (req, res) => {
  res.render("passport/private", { user: req.user });
});

module.exports = passportRouter;
