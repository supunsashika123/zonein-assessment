"use strict";

const DbService	= require("moleculer-db");
let User = require("../models/user");

module.exports = function(collection) {
	const cacheCleanEventName = `cache.clean.${collection}`;

	const schema = {
		mixins: [DbService],

		events: {
			async [cacheCleanEventName]() {
				if (this.broker.cacher) {
					await this.broker.cacher.clean(`${this.fullName}.*`);
				}
			}
		},

		methods: {
			async entityChanged(type, json, ctx) {
				ctx.broadcast(cacheCleanEventName);
			}
		},
	};

	const MongoAdapter = require("moleculer-db-adapter-mongoose");

	schema.adapter = new MongoAdapter(process.env.MONGO_URI);
	//setting user model
	schema.model = User;
	schema.collection = collection;

	return schema;
};
