const router = require("express").Router();
const User = require("../models/User");
const bcrypt = require("bcrypt");

//UPDATE USER
router.put("/:id", async (req, res) => {
  if (req.body.userId === req.params.id || req.body.isAdmin) {
    if (req.body.password) {
      try {
        const salt = await bcrypt.genSalt(10);
        req.body.password = await bcrypt.hash(req.body.password, salt);
      } catch (err) {
        return res.status(500).json(err);
      }
    }
    try {
      const user = await User.findByIdAndUpdate(req.params.id, {
        $set: req.body,
      });
      res.status(200).json("Account has been updated");
    } catch (err) {
      return res.status(500).json(err);
    }
  } else {
    return res.status(403).json("You can only update your account");
  }
});

//DELETE USER
router.delete("/:id", async (req, res) => {
  if (req.body.userId === req.params.id || req.body.isAdmin) {
    try {
      await User.findByIdAndDelete(req.params.id);
      res.status(200).json("Account has been deleted");
    } catch (err) {
      return res.status(500).json(err);
    }
  } else {
    return res.status(403).json("You can only delete your account");
  }
});

//GET ALL USER
// TODO: Remove password and updatedAt in response
router.get("/", async (req, res) => {
  try {
    // const userId = req.query.userId;
    // const username = req.query.username;
    const users = await User.find();
    // const modifiedUsers = users.map((password, updatedAt, ...other) => other)
    // const { password, updatedAt, ...other } = users._doc;
    // let modifiedUsers = []
    // for (let user in users) {
    //   const { password, updatedAt, ...other } = user
    //   modifiedUsers.push(other)
    // }
    // console.log(modifiedUsers);
    res.status(200).json(users);
  } catch (err) {
    res.status(500).json(err);
  }
});

//GET USER BY ID
router.get("/:id", async (req, res) => {
  try {
    // const userId = req.query.userId;
    // const username = req.query.username;
    const user = await User.findById(req.params.id);
    const { password, updatedAt, ...other } = user._doc;
    res.status(200).json(other);
  } catch (err) {
    res.status(500).json(err);
  }
});

//FOLLOW USER
router.put("/:id/follow", async (req, res) => {
  if (req.body.userId !== req.params.id) {
    try {
      const user = await User.findById(req.params.id);
      const currentUser = await User.findById(req.body.userId);
      if (!user.followers.includes(req.body.userId)) {
        await user.updateOne({ $push: { followers: req.body.userId } });
        await currentUser.updateOne({ $push: { followings: req.params.id } });
        res.status(200).json("User has been followed");
      } else {
        res.status(403).json("You already follow this user");
      }
    } catch (err) {
      res.status(500).json(err);
    }
  } else {
    res.status(403).json("You can't follow yourself");
  }
});

//UNFOLLOW USER
router.put("/:id/unfollow", async (req, res) => {
  if (req.body.userId !== req.params.id) {
    try {
      const user = await User.findById(req.params.id);
      const currentUser = await User.findById(req.body.userId);
      if (user.followers.includes(req.body.userId)) {
        await user.updateOne({ $pull: { followers: req.body.userId } });
        await currentUser.updateOne({ $pull: { followings: req.params.id } });
        res.status(200).json("User has been unfollowed");
      } else {
        res.status(403).json("You don't follow this user");
      }
    } catch (err) {
      res.status(500).json(err);
    }
  } else {
    res.status(403).json("You can't unfollow yourself");
  }
});

module.exports = router;
