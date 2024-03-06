const mongoose = require("mongoose");

const Device = mongoose.model(
  "Device",
  new mongoose.Schema({
    deviceLogin: String
  })
);

module.exports = Device;
