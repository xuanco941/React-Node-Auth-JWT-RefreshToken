const config = require("../config/auth.config");
const db = require("../models");
const User = db.user;
const Role = db.role;
const Device = db.device;

var jwt = require("jsonwebtoken");
var bcrypt = require("bcryptjs");

exports.signup = (req, res) => {
  const user = new User({
    username: req.body.username,
    email: req.body.email,
    password: bcrypt.hashSync(req.body.password, 8)
  });

  user.save((err, user) => {
    if (err) {
      res.status(500).send({ message: err });
      return;
    }

    if (req.body.roles) {
      Role.find(
        {
          name: { $in: req.body.roles }
        },
        (err, roles) => {
          if (err) {
            res.status(500).send({ message: err });
            return;
          }

          user.roles = roles.map(role => role._id);
          user.save(err => {
            if (err) {
              res.status(500).send({ message: err });
              return;
            }

            res.send({ message: "User was registered successfully!" });
          });
        }
      );
    } else {
      Role.findOne({ name: "user" }, (err, role) => {
        if (err) {
          res.status(500).send({ message: err });
          return;
        }

        user.roles = [role._id];
        user.save(err => {
          if (err) {
            res.status(500).send({ message: err });
            return;
          }

          res.send({ message: "User was registered successfully!" });
        });
      });
    }
  });
};

exports.signin = (req, res) => {
  User.findOne({
    username: req.body.username
  })
    .populate("roles", "-__v")
    .exec((err, user) => {
      if (err) {
        res.status(500).send({ message: err });
        return;
      }

      if (!user) {
        return res.status(404).send({ message: "User Not found." });
      }

      var passwordIsValid = bcrypt.compareSync(
        req.body.password,
        user.password
      );

      if (!passwordIsValid) {
        return res.status(401).send({
          accessToken: null,
          message: "Invalid Password!"
        });
      }

      const token = jwt.sign({ id: user.id },
        config.secret,
        {
          algorithm: 'HS256',
          allowInsecureKeySizes: true,
          expiresIn: 30, // 30s
        });
      const refreshToken = jwt.sign({ id: user.id },
        config.refreshSecret,
        {
          algorithm: 'HS256',
          allowInsecureKeySizes: true,
          expiresIn: 86400, // 24 hours
        });

      let deviceLogin = new Device({ deviceLogin: refreshToken });
      deviceLogin.save((err, device) => {
        if (err) {
          console.error(err);
        } else {
          console.log(device);
        }
      })
      var authorities = [];

      for (let i = 0; i < user.roles.length; i++) {
        authorities.push("ROLE_" + user.roles[i].name.toUpperCase());
      }
      res.status(200).send({
        id: user._id,
        username: user.username,
        email: user.email,
        roles: authorities,
        accessToken: token,
        refreshToken: refreshToken
      });
    });
};

exports.GetAccessToken = (req, res) => {
  const refreshToken = req.body.refreshToken;

  if (!refreshToken) {
    return res.status(403).send({ message: 'Refresh token is required.' });
  }


  jwt.verify(refreshToken, config.refreshSecret, (err, decoded) => {
    console.log(decoded);
    if (err) {
      return res.status(401).send({ message: 'Invalid refresh token.' });
    }

    Device.findOne({ deviceLogin: refreshToken }, (err, obj) => {
      if (err || !obj) {
        return res.status(401).send({ message: 'Invalid refresh token.' });
      }
      else {
        // Generate a new access token
        const newAccessToken = jwt.sign({ id: decoded.id },
          config.secret,
          {
            algorithm: 'HS256',
            allowInsecureKeySizes: true,
            expiresIn: 30, // 30s
          });

        return res.status(200).send({ accessToken: newAccessToken });
      }
    });


  });
};