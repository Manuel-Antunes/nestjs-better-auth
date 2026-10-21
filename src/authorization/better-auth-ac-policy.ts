import { Inject } from "@nestjs/common";
import type { ExecutionContext } from "@nestjs/common";
import { AuthService } from "../auth-service.ts";
import type { BetterAuthACPolicyMetadata } from "../access-control.ts";
import { BETTER_AUTH_AC_POLICY } from "../symbols.ts";
import type { BetterAuthUser } from "../types.ts";
import { getRequestFromContext } from "../utils.ts";
import { memberHasPermission } from "./organization.ts";

export interface BetterAuthACPolicyDefinition<
	TRole extends string,
	TAction extends string,
> {
	/** The Better Auth resource (statement key) this policy owns. One policy per resource and scope. */
	resource: string;
	/**
	 * Every action of the resource. Required when the generics are enums, because
	 * types are erased at runtime. Defaults to the union of the actions in `statements`.
	 */
	actions?: readonly TAction[];
	/** Role → allowed actions. Becomes `ac.newRole({ [resource]: actions })` for each role. */
	statements: Partial<Record<TRole, readonly TAction[]>>;
	/** An action that expands to every action of the resource when roles are built (e.g. 'manage'). */
	wildcard?: TAction;
}

/** One ability per action, typed so `@Can(Policy, 'create')` is checked at compile time. */
export type BetterAuthACAbilities<TAction extends string> = {
	// Keys are the string values, so enum members work with @Can(Policy, 'create').
	[A in TAction as `${A}`]: (user: BetterAuthUser | null) => Promise<boolean>;
};

/** Type-only: `checkPermission` is `protected` so it is not an ability of the policy. */
declare abstract class BetterAuthACPolicyBase<TAction extends string> {
	readonly authService: AuthService;
	protected checkPermission(
		user: BetterAuthUser | null,
		action: TAction,
	): Promise<boolean>;
}

export type BetterAuthACPolicyClass<TAction extends string> =
	abstract new () => BetterAuthACPolicyBase<TAction> &
		BetterAuthACAbilities<TAction>;

export type BetterAuthOrganizationACAbilities<TAction extends string> = {
	[A in TAction as `${A}`]: (
		user: BetterAuthUser | null,
		organizationId: string | null | undefined,
	) => Promise<boolean>;
};

/** Type-only: see {@link BetterAuthACPolicyBase}. */
declare abstract class BetterAuthOrganizationACPolicyBase<
	TAction extends string,
> {
	readonly authService: AuthService;
	protected checkPermission(
		user: BetterAuthUser | null,
		action: TAction,
		organizationId: string | null | undefined,
	): Promise<boolean>;
}

export type BetterAuthOrganizationACPolicyClass<TAction extends string> =
	abstract new () => BetterAuthOrganizationACPolicyBase<TAction> &
		BetterAuthOrganizationACAbilities<TAction>;

const RESERVED = new Set([
	"before",
	"constructor",
	"authService",
	"checkPermission",
]);

/** The abilities of a policy: its `actions`, or every action its `statements` grant. Rejects names Nest never treats as abilities. */
function resolveActions<TRole extends string, TAction extends string>(
	definition: BetterAuthACPolicyDefinition<TRole, TAction>,
): TAction[] {
	const actions =
		definition.actions ??
		Object.values<readonly TAction[] | undefined>(
			definition.statements,
		).flatMap((granted) => granted ?? []);
	const unique = [...new Set(actions)];

	for (const action of unique) {
		if (RESERVED.has(action))
			throw new Error(
				`Action '${action}' of resource '${definition.resource}' is reserved by @nestjs/authorization or the policy and can't be an ability name.`,
			);
	}
	if (definition.wildcard && !unique.includes(definition.wildcard))
		throw new Error(
			`The wildcard '${definition.wildcard}' of resource '${definition.resource}' is not one of its actions.`,
		);
	return unique;
}

/** Shared by the user and the organization scope, which differ in their ability arguments. */
function createPolicyBase<TRole extends string, TAction extends string>(
	scope: BetterAuthACPolicyMetadata["scope"],
	definition: BetterAuthACPolicyDefinition<TRole, TAction>,
	check: (
		authService: AuthService,
		user: BetterAuthUser,
		action: TAction,
		// biome-ignore lint/suspicious/noExplicitAny: see above
		...args: any[]
	) => Promise<boolean>,
): abstract new () => unknown {
	const actions = resolveActions(definition);

	abstract class AccessControlPolicy {
		// Property injection, like SessionCookieProvider's SessionService in
		// @nestjs/authentication: subclasses declare their own constructor
		// dependencies without forwarding this one.
		@Inject(AuthService) readonly authService!: AuthService;

		async checkPermission(
			user: BetterAuthUser | null,
			action: TAction,
			// biome-ignore lint/suspicious/noExplicitAny: see above
			...args: any[]
		): Promise<boolean> {
			// Guests are denied, and Nest answers 401 for them.
			if (!user) return false;
			return check(this.authService, user, action, ...args);
		}
	}

	for (const action of actions) {
		Object.defineProperty(AccessControlPolicy.prototype, action, {
			value(
				this: AccessControlPolicy,
				user: BetterAuthUser | null,
				// biome-ignore lint/suspicious/noExplicitAny: see above
				...args: any[]
			) {
				return this.checkPermission(user, action, ...args);
			},
			writable: true,
			configurable: true,
		});
	}

	Reflect.defineMetadata(
		BETTER_AUTH_AC_POLICY,
		{ scope, ...definition, actions } satisfies BetterAuthACPolicyMetadata,
		AccessControlPolicy,
	);
	return AccessControlPolicy;
}

/**
 * Base class of a `@nestjs/authorization` policy backed by Better Auth's
 * `admin()` plugin access control. Each action becomes an ability, and the
 * `ac` and `roles` the plugin needs are built from the policy by
 * `BetterAuthAccessControl.admin()`.
 *
 * @example
 * ```ts
 * @Policy()
 * export class PostPolicy extends BetterAuthACPolicy<Roles, Operations>({
 *   resource: 'post',
 *   actions: Object.values(Operations),
 *   wildcard: Operations.MANAGE,
 *   statements: { [Roles.ADMIN]: [Operations.MANAGE], [Roles.USER]: [Operations.CREATE] },
 * }) {}
 * ```
 */
export function BetterAuthACPolicy<
	TRole extends string,
	TAction extends string,
>(
	definition: BetterAuthACPolicyDefinition<TRole, TAction>,
): BetterAuthACPolicyClass<TAction> {
	return createPolicyBase(
		"user",
		definition,
		async (authService, user, action) => {
			// biome-ignore lint/suspicious/noExplicitAny: the API only exists with the admin plugin
			const api = authService.api as any;
			const result = await api.userHasPermission({
				body: {
					userId: user.id,
					permissions: { [definition.resource]: [action] },
				},
			});
			return result?.success === true;
		},
	) as unknown as BetterAuthACPolicyClass<TAction>;
}

/**
 * Like {@link BetterAuthACPolicy}, for the `organization()` plugin. Policies
 * are singletons, so the organization reaches each ability as an argument:
 * use {@link activeOrganization} in `@Can()`, or pass it to
 * `AuthorizationService`.
 */
export function BetterAuthOrganizationACPolicy<
	TRole extends string,
	TAction extends string,
>(
	definition: BetterAuthACPolicyDefinition<TRole, TAction>,
): BetterAuthOrganizationACPolicyClass<TAction> {
	return createPolicyBase(
		"organization",
		definition,
		async (
			authService,
			user,
			action,
			organizationId: string | null | undefined,
		) => {
			if (!organizationId) return false;
			return memberHasPermission(authService, user.id, organizationId, {
				[definition.resource]: [action],
			});
		},
	) as unknown as BetterAuthOrganizationACPolicyClass<TAction>;
}

/**
 * `@Can()` args resolver: the active organization of the session that
 * `@nestjs/authentication`'s guard resolved.
 *
 * @example
 * ```ts
 * @Can(PostOrganizationPolicy, 'create', activeOrganization)
 * ```
 */
export const activeOrganization = async (context: ExecutionContext) => {
	const request = await getRequestFromContext(context);
	return [
		(request?.session?.activeOrganizationId as string | null | undefined) ??
			null,
	] as const;
};
