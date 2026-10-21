import { getOrgAdapter, hasPermission } from "better-auth/plugins";
import type { AuthService } from "../auth-service.ts";
import { findPlugin } from "../authentication/utils.ts";

// biome-ignore lint/suspicious/noExplicitAny: the organization plugin's option types vary by configuration
type OrganizationOptions = any;

async function organizationContext(authService: AuthService) {
	const ctx = await authService.instance.$context;
	const options: OrganizationOptions =
		findPlugin(authService.instance, "organization")?.options ?? {};
	return { ctx, options };
}

/** The member row of `userId` in `organizationId`, or `null`. */
export async function findMember(
	authService: AuthService,
	userId: string,
	organizationId: string,
): Promise<{ role: string } | null> {
	const { ctx, options } = await organizationContext(authService);
	return getOrgAdapter(ctx, options).findMemberByOrgId({
		userId,
		organizationId,
	});
}

/**
 * Whether `userId` has `permissions` in `organizationId`, with the member's
 * role. Needs no request headers, so it also works in queue workers. Merges
 * the roles stored in `organizationRole` when `dynamicAccessControl` is on.
 */
export async function memberHasPermission(
	authService: AuthService,
	userId: string,
	organizationId: string,
	permissions: Record<string, string[]>,
): Promise<boolean> {
	const { ctx, options } = await organizationContext(authService);
	const member = await getOrgAdapter(ctx, options).findMemberByOrgId({
		userId,
		organizationId,
	});
	if (!member) return false;

	// hasPermission only reads `ctx.context` (its adapter and logger).
	return hasPermission(
		{ role: member.role, options, organizationId, permissions },
		{ context: ctx } as Parameters<typeof hasPermission>[1],
	);
}

/**
 * Whether a role value (a string, a comma-separated string or an array)
 * matches any of the required roles.
 */
export function matchesRequiredRole(
	role: string | string[] | undefined | null,
	requiredRoles: readonly string[],
): boolean {
	if (!role) return false;
	const roles = Array.isArray(role) ? role : role.split(",");
	return roles.some((r) => requiredRoles.includes(r.trim()));
}
