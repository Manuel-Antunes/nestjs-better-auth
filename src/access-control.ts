import { Injectable } from "@nestjs/common";
import { DiscoveryService } from "@nestjs/core";
import { createAccessControl } from "better-auth/plugins/access";
import {
	adminAc,
	defaultStatements as adminDefaultStatements,
	userAc,
} from "better-auth/plugins/admin/access";
import {
	adminAc as orgAdminAc,
	defaultStatements as orgDefaultStatements,
	memberAc,
	ownerAc,
} from "better-auth/plugins/organization/access";
import { BETTER_AUTH_AC_POLICY } from "./symbols.ts";

type StatementsMap = Record<string, readonly string[]>;

export type AccessControlScope = "user" | "organization";

/** What `BetterAuthACPolicy()` / `BetterAuthOrganizationACPolicy()` attach to a class. */
export interface BetterAuthACPolicyMetadata {
	scope: AccessControlScope;
	resource: string;
	actions: readonly string[];
	statements: Record<string, readonly string[] | undefined>;
	wildcard?: string;
}

export interface BuildAccessControlOptions {
	/**
	 * Keep Better Auth's own statements and roles (`user`, `session`, `member`,
	 * `invitation`…) so its built-in endpoints keep working. Better Auth's docs
	 * warn that custom roles otherwise override the defaults.
	 * @default true
	 */
	defaults?: boolean;
}

type Defaults = {
	statements: StatementsMap;
	roles: Record<string, StatementsMap>;
};

const ADMIN_DEFAULTS: Defaults = {
	statements: adminDefaultStatements,
	roles: { admin: adminAc.statements, user: userAc.statements },
};

const ORGANIZATION_DEFAULTS: Defaults = {
	statements: orgDefaultStatements,
	roles: {
		owner: ownerAc.statements,
		admin: orgAdminAc.statements,
		member: memberAc.statements,
	},
};

/**
 * Builds the `ac` and `roles` Better Auth's `admin()` and `organization()`
 * plugins take, from the `BetterAuthACPolicy()` / `BetterAuthOrganizationACPolicy()`
 * classes registered in the application.
 *
 * Nest scans every module, and so knows every provider's class, before it
 * instantiates anything, which is why this works inside a `forRootAsync()`
 * factory. Policies in lazily loaded modules are not seen.
 */
@Injectable()
export class BetterAuthAccessControl {
	constructor(private readonly discovery: DiscoveryService) {}

	/** Spread into `admin({...})`. */
	admin(options: BuildAccessControlOptions = {}) {
		return this.build(
			"user",
			options.defaults === false ? undefined : ADMIN_DEFAULTS,
		);
	}

	/** Spread into `organization({...})`. */
	organization(options: BuildAccessControlOptions = {}) {
		return this.build(
			"organization",
			options.defaults === false ? undefined : ORGANIZATION_DEFAULTS,
		);
	}

	private build(scope: AccessControlScope, base?: Defaults) {
		const statements: Record<string, string[]> = {};
		for (const [resource, actions] of Object.entries(base?.statements ?? {})) {
			statements[resource] = [...actions];
		}
		const grants: Record<string, Record<string, string[]>> = {};
		for (const [role, roleStatements] of Object.entries(base?.roles ?? {})) {
			grants[role] = {};
			for (const [resource, actions] of Object.entries(roleStatements)) {
				grants[role][resource] = [...actions];
			}
		}

		// Compared by class: distinct classes can share a name.
		const seen = new Map<string, { metatype: unknown; name: string }>();
		for (const { metatype } of this.discovery.getProviders()) {
			const definition =
				metatype &&
				(Reflect.getMetadata(BETTER_AUTH_AC_POLICY, metatype) as
					| BetterAuthACPolicyMetadata
					| undefined);
			if (!definition || definition.scope !== scope) continue;

			const owner = seen.get(definition.resource);
			if (owner && owner.metatype !== metatype) {
				throw new Error(
					`Two ${scope} policies define resource '${definition.resource}': ${owner.name} and ${metatype.name}.`,
				);
			}
			seen.set(definition.resource, { metatype, name: metatype.name });

			statements[definition.resource] = [...definition.actions];
			for (const [role, actions] of Object.entries(definition.statements)) {
				if (!actions) continue;
				const expanded =
					definition.wildcard && actions.includes(definition.wildcard)
						? definition.actions
						: actions;
				// biome-ignore lint/suspicious/noAssignInExpressions: lazily create the role's grants
				(grants[role] ??= {})[definition.resource] = [...expanded];
			}
		}

		const ac = createAccessControl(statements);
		const roles = Object.fromEntries(
			Object.entries(grants).map(([name, roleStatements]) => [
				name,
				ac.newRole(roleStatements),
			]),
		);
		return { ac, roles };
	}
}
