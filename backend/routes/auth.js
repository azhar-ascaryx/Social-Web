const router = require("express").Router();
const User = require("../models/User");
const bcrypt = require("bcrypt");

//REGISTER

router.post("/register", async (req, res) => {
  try {
    // GENERATE NEW PASSWORD
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(req.body.password, salt);
    // CREATE NEW USER
    const newUser = new User({
      username: req.body.username,
      email: req.body.email,
      password: hashedPassword,
    });
    // SAVE NEW USER
    const user = await newUser.save();
    res.status(200).json(user);
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

//LOGIN

router.get("/login", async (req, res) => {
  try {
    // FIND USER BY EMAIL
    const user = await User.findOne({ email: req.body.email });
    // CHECK IF USER EXISTS
    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }
    // CHECK IF PASSWORD IS CORRECT
    const validPassword = await bcrypt.compare(
      req.body.password,
      user.password
    );
    if (!validPassword) {
      return res.status(401).json({ message: "Invalid password" });
    }
    // SEND USER TOKEN
    res.status(200).json(user);
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

module.exports = router;
