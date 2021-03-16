"use strict";
const DbMixin = require("../mixins/db.mixin");
const authMixin = require("../mixins/authorize.mixin");
const bcrypt = require("bcrypt");
const { MoleculerClientError } = require("moleculer").Errors;
const jwt = require("jsonwebtoken");
let customId = require("custom-id");


module.exports = {
	name: "auth",
	version: 1,
	mixins:[DbMixin("users"), authMixin],
	hooks: {
		before: {
			// "*": ["checkIsAuthenticated"],
			hello: ["authenticate", "checkOwner"],

			register: [
				function addTimestamp(ctx) {
					ctx.params.createdAt = new Date();
					return ctx;
				}
			]
		},
		after: {
			get: [
				(ctx, res) => {
					delete res.password;
					return res;
				}
			]
		}
	},

	actions: {
		aaaa: {
			rest: "/aaaa",
			async handler() {
				return "This is restricted";
			}
		},

		"delete-user": {
			role: "super-admin",
			rest:"/delete-user",
			async handler() {
				return "User deleted successfully.";
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
					createdAt: ctx.params.createdAt
				});

				return {status:"success", message:"New user registered successfully.", data:newUser};
			}
		}
	},

	methods: {
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
				if(login.ip_address === ip && login.device === ctx.meta.userAgent)
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
				device : ctx.meta.userAgent
			};

			//update user
			await this.adapter.updateById(user._id, { $set: { loginInfo: [...user.loginInfo,newLogin] } });

			const token_user = { id:user._id , token_id: token_id };

			return await jwt.sign(token_user, process.env.ACCESS_TOKEN_SECRET);
		},

		async authenticateToken(ctx) {
			const authHeader = ctx.meta.authorization;

			const bearer = authHeader && authHeader.split(" ")[0];
			// if (bearer !== "Bearer")
			// 	return res.sendStatus(401);

			const token = authHeader && authHeader.split(" ")[1];
			// if (token == null)
			// 	return res.sendStatus(401);

			// Blacklist.findOne({ where: {token: token } })
			// 	.then((found) => {
			//
			// 		if (found){
			// 			details={
			// 				"Status":"Failure",
			// 				"Details":"Token blacklisted. Cannot use this token."
			// 			};
			//
			// 			return res.status(401).json(details);
			// 		}
			// 		else {


			jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, async (err, payload) => {
				if (err)
					return "error";
				if(payload){
					const login = await User_Login.findOne({where:{ user_id : payload.id, token_id: payload.token_id}});

					if(login.token_deleted === true) {
						// const blacklist_token = Blacklist.create({
						// 	token:token
						// });
						// return res.sendStatus(401);
						return "token deleted";
					}
				}
				// req.user = payload;
				// next();
				return true;
			});
			// }
			// });

		}
	}
};
