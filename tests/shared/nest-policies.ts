import { Injectable } from "@nestjs/common";
import { Policy } from "@nestjs/authorization";
import {
	BetterAuthACPolicy,
	BetterAuthOrganizationACPolicy,
} from "../../src/authorization/index.ts";
import type { BetterAuthUser } from "../../src/types.ts";

export enum Roles {
	OWNER = "owner",
	ADMIN = "admin",
	MEMBER = "member",
	USER = "user",
}

export enum Operations {
	MANAGE = "manage",
	CREATE = "create",
	UPDATE = "update",
}

export type Post = { id: string; authorId: string };

@Policy()
export class PostPolicy extends BetterAuthACPolicy<Roles, Operations>({
	resource: "post",
	actions: Object.values(Operations),
	wildcard: Operations.MANAGE,
	statements: {
		[Roles.ADMIN]: [Operations.MANAGE],
		[Roles.USER]: [Operations.CREATE],
	},
}) {
	// Authors may always edit their own posts; everyone else needs the 'update' permission.
	override update = async (user: BetterAuthUser | null, post?: Post) => {
		if (user && post?.authorId === user.id) return true;
		return this.checkPermission(user, Operations.UPDATE);
	};
}

@Policy()
export class PostOrganizationPolicy extends BetterAuthOrganizationACPolicy<
	Roles,
	Operations
>({
	resource: "post",
	actions: Object.values(Operations),
	wildcard: Operations.MANAGE,
	statements: {
		[Roles.OWNER]: [Operations.MANAGE],
		[Roles.ADMIN]: [Operations.MANAGE],
		[Roles.MEMBER]: [Operations.CREATE],
	},
}) {}

/** A policy that declares its own constructor dependency next to the mixin's. */
@Injectable()
export class Clock {
	now() {
		return 1;
	}
}

@Policy()
export class ReportPolicy extends BetterAuthACPolicy<Roles, "read">({
	resource: "report",
	statements: { [Roles.ADMIN]: ["read"] },
}) {
	constructor(readonly clock: Clock) {
		super();
	}
}
