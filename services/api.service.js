"use strict";

const ApiGateway = require("moleculer-web");

module.exports = {
	name: "api",
	mixins: [ApiGateway],

	settings: {
		port: process.env.PORT || 3000,
		ip: "0.0.0.0",
		use: [],
		routes: [
			{
				path: "/api",
				whitelist: [
					"**"
				],
				mergeParams: true,
				authentication: false,
				authorization: false,
				autoAliases: true,

				onBeforeCall(ctx, route, req, res) {
					// Set request headers to context meta
					ctx.meta.userAgent = req.headers["user-agent"];
					ctx.meta.xForwardedFor = req.headers["x-forwarded-for"];
					ctx.meta.remoteAddress = req.connection.remoteAddress;
					ctx.meta.authorization = req.headers["authorization"];
				},

				bodyParsers: {
					json: {
						strict: false,
						limit: "1MB"
					},
					urlencoded: {
						extended: true,
						limit: "1MB"
					}
				},

				mappingPolicy: "all", // Available values: "all", "restrict"
				logging: true
			}
		],

		log4XXResponses: false,
		logRequestParams: null,
		logResponseData: null,

		assets: {
			folder: "public",
		}
	},
};
