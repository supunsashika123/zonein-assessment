const jwt = require("jsonwebtoken");

module.exports = {
	methods: {
		/**
		 * Authenticates the request by checking token validity.
		 *
		 * @param ctx
		 * @returns {Promise<void>}
		 */
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
					throw new Error("User not found");
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

		/**
		 * Checks whether the action is allowed for respective user role.
		 *
		 * @param allowedRoles
		 * @param userRole
		 * @returns {boolean|*}
		 */
		checkUserRoles: function (allowedRoles, userRole) {
			if(!allowedRoles){
				return true;
			}

			return allowedRoles.some((role) => role === userRole);
		}
	}
};
