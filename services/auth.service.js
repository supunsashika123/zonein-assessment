"use strict";

const { MoleculerClientError } = require("moleculer").Errors;
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");
let customId = require("custom-id");
const authMixin = require("../mixins/authorize.mixin");
const DbMixin = require("../mixins/db.mixin");


module.exports = {
	name: "auth",

	version: 1,

	mixins:[DbMixin("users"), authMixin],

	hooks: {
		before: {
			"athlete-only": ["authenticate"],

			common: ["authenticate"],

			logout: ["authenticate"],

			delete: ["authenticate"],

			register: [
				function addTimestamp(ctx) {
					ctx.params.createdAt = new Date();
					return ctx;
				}
			]
		},
	},

	actions: {
		"athlete-only": {
			rest: "GET /athlete-only",
			roles: ["athlete"],
			async handler() {
				return "This route is only for athletes.";
			}
		},

		common: {
			rest: "GET /common",
			async handler() {
				return "Common route is allowed for all user roles.";
			}
		},

		delete: {
			roles: ["super-admin"],
			rest:"POST /delete",
			async handler() {
				return "User deleted successfully.";
			}
		},

		logout: {
			rest: "POST /logout",

			async handler(ctx) {
				const authHeader = ctx.meta.authorization;
				const token = authHeader && authHeader.split(" ")[1];
				let payload = await jwt.verify(token, process.env.ACCESS_TOKEN_SECRET);
				const user = await this.adapter.findById(payload.id);

				await this.adapter.updateById(user._id, { $set: { loginInfo: [] } });

				return "User logged out successfully";
			}
		},

		login: {
			rest: "POST /login",

			params: {
				email: "email",
				password: "string",
			},

			async handler(ctx) {
				let user = await this.adapter.findOne({email:ctx.params.email});
				if(!user) {
					return this.Promise.reject(new MoleculerClientError("Invalid credentials", 400));
				}

				const validPassword = await bcrypt.compare(ctx.params.password, user.password);
				if(!validPassword) {
					return this.Promise.reject(new MoleculerClientError("Invalid credentials", 400));
				}

				delete user.password;
				let token = await this.createToken(ctx, user);
				return {user,token};
			}
		},

		register: {
			rest: "POST /register",

			params: {
				email: "email|unique",
				password: "string",
				role: "string"
			},

			async handler(ctx) {
				//validate unique email
				let duplicatedEmailUser = await this.adapter.findOne({email:ctx.params.email});
				if(duplicatedEmailUser) {
					return this.Promise.reject(new MoleculerClientError("Email is already taken!", 400));
				}

				const salt = await bcrypt.genSalt(10);
				ctx.params.password = await bcrypt.hash(ctx.params.password, salt);

				let newUser = await this.adapter.insert({
					email: ctx.params.email,
					password: ctx.params.password,
					role: ctx.params.role,
					createdAt: ctx.params.createdAt,
					loginInfo:[]
				});

				return {status:"success", message:"New user registered successfully.", data:newUser};
			}
		}
	},

	methods: {
		/**
		 * Creates a new token for user. Blacklists all previous tokens for same device.
		 *
		 * @param ctx
		 * @param user
		 * @returns {Promise<*>}
		 */
		async createToken(ctx, user) {
			const token_id = await customId({
				user_id : user._id,
				date : Date.now(),
				randomLength: 4
			});

			let ip = (ctx.meta.xForwardedFor || "").split(",").pop().trim() ||
				ctx.meta.remoteAddress;

			//expire all tokens for same device and ip
			user.loginInfo.forEach((login) => {
				if (login.ip_address === ip && login.device === ctx.meta.userAgent)
					login.token_deleted = true;
			});

			const token_secret = await customId({
				token_secret : ip,
				date : Date.now(),
				randomLength: 8
			});

			let newLogin = {
				token_id : token_id,
				token_secret : token_secret ,
				ip_address : ip ,
				device : ctx.meta.userAgent,
				token_deleted: false
			};

			//update user
			await this.adapter.updateById(user._id, { $set: { loginInfo: [...user.loginInfo,newLogin] } });

			const token_user = { id:user._id , token_id: token_id };

			return await jwt.sign(token_user, process.env.ACCESS_TOKEN_SECRET);
		},
	}
};
