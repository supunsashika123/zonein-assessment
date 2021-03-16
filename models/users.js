"use strict";

const mongoose = require("mongoose");
const Schema = mongoose.Schema;

const UserSchema = new Schema({
	email: {
		type: String,
		trim: true,
		required: true,
		unique:true
	},
	password: {
		type: String,
		trim: true,
		required: true,
	},
	role: {
		enum:["admin","super-admin"],
		type: String,
		required: true,
	},
	login_info: {
		type: Array,
		default: []
	}
}, {
	timestamps: true
});


module.exports = mongoose.model("User", UserSchema);
