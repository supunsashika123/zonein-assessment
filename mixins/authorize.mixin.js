const jwt = require("jsonwebtoken");

module.exports = {
	methods: {
		authenticate: async function (ctx) {
			const authHeader = ctx.meta.authorization;

			const bearer = authHeader && authHeader.split(" ")[0];
			if (bearer !== "Bearer")
				throw new Error("Unauthenticated");

			const token = authHeader && authHeader.split(" ")[1];
			if (token == null)
				throw new Error("Unauthenticated");

			try {
				let payload = await jwt.verify(token, process.env.ACCESS_TOKEN_SECRET);
				const user = await this.adapter.findById(payload.id);

				if(!user){
					throw new Error("No user found");
				}

				let isBlackListedToken = true;

				user.loginInfo.forEach((login) => {
					if (login.token_id === payload.token_id && login.token_deleted === false) {
						isBlackListedToken = false;
					}
				});

				if (isBlackListedToken) {
					throw new Error("Blacklisted token");
				}

				if(!this.checkUserRoles(ctx.action.roles, user.role)){
					throw new Error("Forbidden");
				}

			} catch (e) {
				throw new Error(e);
			}
		},

		checkUserRoles: function (allowedRoles, userRole) {
			if(!allowedRoles){
				return true;
			}

			return allowedRoles.some((role) => role === userRole);
		}
	}
};
