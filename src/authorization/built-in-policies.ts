import { Inject, Module } from "@nestjs/common";
import type { ExecutionContext } from "@nestjs/common";
import { applyDecorators } from "@nestjs/common";
import { Can, Policy } from "@nestjs/authorization";
import type {
	MemberHasPermissionOptions,
	UserHasPermissionOptions,
} from "../decorators.ts";
import { AuthService } from "../auth-service.ts";
import type { BetterAuthUser } from "../types.ts";
import { activeOrganization } from "./better-auth-ac-policy.ts";
import {
	findMember,
	matchesRequiredRole,
	memberHasPermission,
} from "./organization.ts";

/**
 * The checks behind `Roles`, `OrgRoles`, `RequireActiveOrg`,
 * `UserHasPermission` and `MemberHasPermission` in `authentication: 'nestjs'`
 * mode. Provided by `BetterAuthAuthorizationModule`.
 */
@Policy()
export class BetterAuthPermissionPolicy {
	constructor(@Inject(AuthService) private readonly authService: AuthService) {}

	/** `user.role` (admin plugin) matches one of `roles`. */
	hasRole(user: BetterAuthUser | null, roles: string[]): boolean {
		return !!user && matchesRequiredRole(user.role, roles);
	}

	/** The session has an active organization. */
	hasActiveOrganization(
		user: BetterAuthUser | null,
		organizationId: string | null | undefined,
	): boolean {
		return !!user && !!organizationId;
	}

	/** The user's member role in the organization matches one of `roles`. */
	async hasOrganizationRole(
		user: BetterAuthUser | null,
		organizationId: string | null | undefined,
		roles: string[],
	): Promise<boolean> {
		if (!user || !organizationId) return false;
		const member = await findMember(this.authService, user.id, organizationId);
		return matchesRequiredRole(member?.role, roles);
	}

	async userHasPermission(
		user: BetterAuthUser | null,
		options: UserHasPermissionOptions,
	): Promise<boolean> {
		if (!user) return false;

		const body: {
			userId?: string;
			role?: string;
			permissions?: Record<string, string[]>;
		} = { userId: options.userId ?? user.id };
		if (options.role) body.role = options.role;
		body.permissions = options.permission ?? options.permissions;

		try {
			// biome-ignore lint/suspicious/noExplicitAny: the API only exists with the admin plugin
			const api = this.authService.api as any;
			const result = await api.userHasPermission({ body });
			return result?.success === true;
		} catch (error) {
			console.error("Permission check error:", error);
			return false;
		}
	}

	async memberHasPermission(
		user: BetterAuthUser | null,
		organizationId: string | null | undefined,
		permissions: Record<string, string[]>,
	): Promise<boolean> {
		if (!user || !organizationId) return false;
		try {
			return await memberHasPermission(
				this.authService,
				user.id,
				organizationId,
				permissions,
			);
		} catch (error) {
			console.error("Member permission check error:", error);
			return false;
		}
	}
}

/** Provides the built-in policies. Import it where `Roles`, `OrgRoles`… are used. */
@Module({
	providers: [BetterAuthPermissionPolicy],
	exports: [BetterAuthPermissionPolicy],
})
export class BetterAuthAuthorizationModule {}

/** Requires an active organization in the session. Does not check any role. */
export const RequireActiveOrg = (): ClassDecorator & MethodDecorator =>
	Can(BetterAuthPermissionPolicy, "hasActiveOrganization", activeOrganization);

/**
 * `user.role` must match one of `roles` (admin plugin). `@Can()` version of
 * the main entry's `Roles()`.
 */
export const Roles = (roles: string[]): ClassDecorator & MethodDecorator =>
	Can(BetterAuthPermissionPolicy, "hasRole", () => [roles] as const);

/**
 * The organization member role must match one of `roles`, in the session's
 * active organization. `@Can()` version of the main entry's `OrgRoles()`.
 */
export const OrgRoles = (roles: string[]): ClassDecorator & MethodDecorator => {
	const decorator = Can(
		BetterAuthPermissionPolicy,
		"hasOrganizationRole",
		async (context: ExecutionContext) =>
			[...(await activeOrganization(context)), roles] as const,
	);
	return applyDecorators(RequireActiveOrg(), decorator) as ClassDecorator &
		MethodDecorator;
};

/** `@Can()` version of the main entry's `UserHasPermission()`. */
export const UserHasPermission = (
	options: UserHasPermissionOptions,
): ClassDecorator & MethodDecorator => {
	if (!options.permission && !options.permissions) {
		throw new Error(
			"UserHasPermission: Either 'permission' or 'permissions' must be provided",
		);
	}
	return Can(
		BetterAuthPermissionPolicy,
		"userHasPermission",
		() => [options] as const,
	);
};

/** `@Can()` version of the main entry's `MemberHasPermission()`. */
export const MemberHasPermission = (
	options: MemberHasPermissionOptions,
): ClassDecorator & MethodDecorator => {
	if (!options.permissions) {
		throw new Error("MemberHasPermission: 'permissions' must be provided");
	}
	return Can(
		BetterAuthPermissionPolicy,
		"memberHasPermission",
		async (context: ExecutionContext) =>
			[...(await activeOrganization(context)), options.permissions] as const,
	);
};
