const express = require("express");
const router = express.Router();
const User = require("../models/user.js");
const bcrypt = require("bcrypt");

router.get("/sign-up", (req, res) => {
  res.render("auth/sign-up.ejs");
});

router.post("/sign-up", async (req, res) => {
  //check if the user exists
  const userInDatabase = await User.findOne({ username: req.body.username });
  //if yes, reject
  if (userInDatabase) {
    return res.send("Username already taken.");
  }
  //check to confirm that the passwords match
  if (req.body.password !== req.body.confirmPassword) {
    return res.send("Password and Confirm Password must match");
  }

  //hash password
  const hashedPassword = bcrypt.hashSync(req.body.password, 10);
  req.body.password = hashedPassword;

  const user = await User.create(req.body);

  res.send("Form submission accepted!");
});

router.get("/sign-in", (req, res) => {
  res.render("auth/sign-in.ejs");
});

router.post("/sign-in", async (req, res) => {
  const userInDatabase = await User.findOne({ username: req.body.username });
  if (!userInDatabase) {
    return res.status(401).send("Login failed. Please try again.");
  }

  //does the password hash match?
  const validPassword = bcrypt.compareSync(
    req.body.password,
    userInDatabase.password
  );

  //if no, throw error
  if (!validPassword) {
    return res.send("Login failed. Please try again.");
  }

  req.session.user = {
    username: userInDatabase.username,
    _id: userInDatabase._id
  };

  res.redirect("/");
});

// Sign-out route moved outside and fixed
router.get("/sign-out", (req, res) => {
  req.session.destroy();
  res.redirect("/");
});

module.exports = router;