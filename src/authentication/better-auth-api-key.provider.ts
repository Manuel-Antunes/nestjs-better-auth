import {
	type ExecutionContext,
	Inject,
	Injectable,
	Logger,
} from "@nestjs/common";
import {
	ApiKeyProvider,
	type ApiKeySession,
	AuthenticationError,
	AuthenticationRegistry,
	type AuthenticationResult,
} from "@nestjs/authentication";
import {
	type AuthModuleOptions,
	MODULE_OPTIONS_TOKEN,
} from "../auth-module-definition.ts";
import { AuthService } from "../auth-service.ts";
import type { BetterAuthUser } from "../types.ts";
import { findPlugin, toArray } from "./utils.ts";

// biome-ignore lint/suspicious/noExplicitAny: the api-key record varies by plugin version
type Options = Record<string, any>;

/**
 * Authenticates with Better Auth's `apiKey()` plugin.
 *
 * Better Auth owns the key format and how keys are hashed and stored, so this
 * extends `ApiKeyProvider` (for `@Authenticate({ providers: [ApiKeyProvider] })`
 * and `instanceof` checks) but delegates the whole check to `verifyApiKey`:
 * its rate limits, remaining counts and key permissions still apply.
 *
 * Registers itself only when the `api-key` plugin is configured. Leave
 * `enableSessionForAPIKeys` off: otherwise `getSession()` turns a key into a
 * regular session and `BetterAuthSessionProvider` accepts it first.
 */
@Injectable()
export class BetterAuthApiKeyProvider extends ApiKeyProvider<BetterAuthUser> {
	private readonly headerNames: string[];
	private readonly apiRealm: string;
	private readonly logger = new Logger(BetterAuthApiKeyProvider.name);

	constructor(
		@Inject(AuthService) private readonly authService: AuthService,
		@Inject(MODULE_OPTIONS_TOKEN) options: AuthModuleOptions,
		@Inject(AuthenticationRegistry) registry: AuthenticationRegistry,
	) {
		const realm = options.apiKey?.realm ?? "api";
		// The prefix is unused: authenticate() is overridden.
		super({ prefix: "ba", realm });
		this.apiRealm = realm;

		const plugin = findPlugin(options.auth, "api-key");
		this.headerNames = toArray(
			(plugin?.options?.apiKeyHeaders as string | string[] | undefined) ??
				"x-api-key",
		).map((name) => name.toLowerCase());

		if (plugin) {
			registry.registerProvider(this, {
				order: options.providerOrder?.apiKey ?? 2,
			});
		}
	}

	override async authenticate(
		context: ExecutionContext,
	): Promise<AuthenticationResult<BetterAuthUser, ApiKeySession> | null> {
		const key = this.headerNames
			.map((name) => this.header(context, name))
			.find(Boolean);
		if (!key) return null;

		// biome-ignore lint/suspicious/noExplicitAny: the API only exists with the api-key plugin
		const api = this.authService.api as any;
		let verified: {
			valid?: boolean;
			error?: { message?: string };
			key?: Options;
		};
		try {
			verified = await api.verifyApiKey({ body: { key } });
		} catch (error) {
			// Some versions throw for a bad key; a store outage stays a 500.
			const status = (error as { statusCode?: number })?.statusCode;
			if (typeof status === "number" && status >= 400 && status < 500) {
				throw this.invalid((error as Error).message);
			}
			throw error;
		}
		const { valid, error, key: record } = verified;
		if (!valid || !record) {
			throw this.invalid(error?.message);
		}

		// `referenceId` since the api-key plugin supports organization-owned keys.
		// Those have no user and are not supported: only user-owned keys sign in.
		const ownerId: string | undefined = record.referenceId ?? record.userId;
		if (record.references === "organization" || !ownerId) {
			throw this.invalid("API key is not owned by a user");
		}

		const ctx = await this.authService.instance.$context;
		const user = await ctx.internalAdapter.findUserById(ownerId);
		if (!user) throw this.invalid("API key owner not found");

		return {
			user: user as BetterAuthUser,
			session: {
				method: "api-key",
				keyId: record.id,
				...(record.expiresAt && { expiresAt: new Date(record.expiresAt) }),
			},
		};
	}

	// Better Auth looks keys up itself; this provider never reaches findKey().
	protected findKey(): never {
		throw new Error(
			"BetterAuthApiKeyProvider delegates verification to Better Auth.",
		);
	}

	/** Keys are created with Better Auth's `createApiKey()`: it owns the key format. */
	override generate(): never {
		throw new Error(
			"Create keys with AuthService.api.createApiKey(): Better Auth owns the key format.",
		);
	}

	/** `WWW-Authenticate` challenge sent with a 401 when no provider found credentials. */
	override challenge(): string {
		return `ApiKey realm="${this.apiRealm}"`;
	}

	/**
	 * One generic message for the client, so it can't tell an expired key from
	 * a disabled or rate limited one. The reason goes to the server's logs.
	 */
	private invalid(reason?: string): AuthenticationError {
		if (reason) this.logger.debug(`API key refused: ${reason}`);
		return new AuthenticationError("Invalid API key", {
			code: "invalid_token",
			challenge: this.challenge(),
		});
	}
}
