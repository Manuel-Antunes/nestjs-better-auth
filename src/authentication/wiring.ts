import { Inject, Injectable, Logger, Optional } from "@nestjs/common";
import type { OnModuleInit } from "@nestjs/common";
import { DiscoveryService } from "@nestjs/core";
import {
	AuthenticationRegistry,
	EmailVerificationHandler,
	MagicLinkHandler,
	OidcAccountResolver,
	PasswordHasher,
	PasswordResetHandler,
} from "@nestjs/authentication";
import { createAuthMiddleware } from "better-auth/api";
import {
	type AuthModuleOptions,
	MODULE_OPTIONS_TOKEN,
} from "../auth-module-definition.ts";
import {
	BIND_PASSWORD_HASHER,
	type BetterAuthPassword,
	PASSWORD_HASHER,
	type NestPasswordHasher,
} from "./better-auth-password.ts";
import { expiresIn, findPlugin } from "./utils.ts";

// biome-ignore lint/suspicious/noExplicitAny: Better Auth's option objects vary by version and plugins
type Options = Record<string, any>;

/**
 * Replaces `parent[key]`. Nest handlers override what the config defines, and
 * the library says which callback it replaced. Unlike hooks these callbacks
 * are not composed: that would send two emails.
 */
function overrideCallback(
	logger: Logger,
	parent: Options,
	path: string,
	key: string,
	callback: (...args: never[]) => unknown,
) {
	if (typeof parent[key] === "function" && !parent[key][PLACEHOLDER]) {
		logger.log(`Nest handler replaces the '${path}.${key}' callback.`);
	}
	parent[key] = callback;
}

const PLACEHOLDER = Symbol("nestjs-better-auth:placeholder");

/**
 * Placeholder for `magicLink({ sendMagicLink })`, whose type requires the
 * callback. The `MagicLinkHandler` discovered at startup replaces it.
 */
export const fromNestHandler = Object.assign(
	async () => {
		throw new Error(
			"No MagicLinkHandler was found. Provide a class extending MagicLinkHandler in one of your modules.",
		);
	},
	{ [PLACEHOLDER]: true },
);

/**
 * Plugs the Nest ports that Better Auth runs itself into Better Auth's
 * configuration, once every provider exists: the email handlers, the OIDC
 * account resolver and `PasswordHasher`. Handlers are discovered with
 * `DiscoveryService`, like `@Hook()` providers, so the app configures none of
 * Nest's own stores for them.
 */
@Injectable()
export class BetterAuthNestWiring implements OnModuleInit {
	private readonly logger = new Logger("BetterAuthNestWiring");

	constructor(
		@Inject(MODULE_OPTIONS_TOKEN) private readonly options: AuthModuleOptions,
		@Inject(DiscoveryService) private readonly discovery: DiscoveryService,
		@Inject(AuthenticationRegistry)
		private readonly registry: AuthenticationRegistry,
		@Optional()
		@Inject(PasswordHasher)
		private readonly hasher?: PasswordHasher,
	) {}

	onModuleInit(): void {
		this.wireEmailHandlers();
		this.wireOidc();
		this.wirePassword();
	}

	private find<T>(type: abstract new (...args: never[]) => T): T | undefined {
		for (const { instance } of this.discovery.getProviders()) {
			if (instance instanceof type) return instance as T;
		}
		return undefined;
	}

	private wireEmailHandlers(): void {
		const auth = this.options.auth.options as Options;

		const passwordReset =
			this.find(PasswordResetHandler) ?? this.registry.handler("passwordReset");
		if (passwordReset) {
			const parent = this.require(
				auth,
				"emailAndPassword",
				"PasswordResetHandler",
				"emailAndPassword: { enabled: true }",
			);
			overrideCallback(
				this.logger,
				parent,
				"emailAndPassword",
				"sendResetPassword",
				(async ({ user, url }: { user: Options; url: string }) =>
					passwordReset.send({
						userId: user.id,
						email: user.email,
						url,
						expiresAt: expiresIn(parent.resetPasswordTokenExpiresIn ?? 3600),
					})) as never,
			);
		}

		const emailVerification =
			this.find(EmailVerificationHandler) ??
			this.registry.handler("emailVerification");
		if (emailVerification) {
			const parent = this.require(
				auth,
				"emailVerification",
				"EmailVerificationHandler",
				"emailVerification: {}",
			);
			overrideCallback(
				this.logger,
				parent,
				"emailVerification",
				"sendVerificationEmail",
				(async ({ user, url }: { user: Options; url: string }) =>
					emailVerification.send({
						userId: user.id,
						email: user.email,
						url,
						expiresAt: expiresIn(parent.expiresIn ?? 3600),
					})) as never,
			);
		}

		const magicLink =
			this.find(MagicLinkHandler) ?? this.registry.handler("magicLink");
		const magicLinkPlugin = findPlugin(this.options.auth, "magic-link");
		if (magicLink && magicLinkPlugin?.options) {
			const pluginOptions = magicLinkPlugin.options as Options;
			overrideCallback(
				this.logger,
				pluginOptions,
				"magicLink",
				"sendMagicLink",
				(async ({ email, url }: { email: string; url: string }) =>
					magicLink.send({
						email,
						url,
						expiresAt: expiresIn(pluginOptions.expiresIn ?? 300),
					})) as never,
			);
		}
	}

	/** `OidcAccountResolver`: decides which local user an external identity belongs to, or refuses the link. */
	private wireOidc(): void {
		const resolver =
			this.find(OidcAccountResolver) ?? this.registry.handler("oidc");
		if (!resolver) return;

		const databaseHooks = this.options.auth.options.databaseHooks as
			| Options
			| undefined;
		if (typeof databaseHooks !== "object" || databaseHooks === null)
			throw new Error(
				"Detected an OidcAccountResolver but Better Auth 'databaseHooks' is not configured. Add an empty 'databaseHooks: {}' object to your betterAuth(...) options.",
			);

		databaseHooks.account ??= {};
		databaseHooks.account.create ??= {};
		const original = databaseHooks.account.create.before;

		databaseHooks.account.create.before = async (
			account: Options,
			ctx: Options | null,
		) => {
			const earlier = original ? await original(account, ctx) : undefined;
			if (earlier === false) return false;
			if (account.providerId === "credential") return earlier;

			// `ctx` is absent when the account is created outside an endpoint.
			const context = ctx?.context ?? (await this.options.auth.$context);
			const user = await context.internalAdapter.findUserById(account.userId);
			const resolved = await resolver.resolveUser(
				{
					provider: account.providerId,
					subject: account.accountId,
					email: user?.email,
					emailVerified: !!user?.emailVerified,
					claims: {},
				},
				{
					accessToken: account.accessToken ?? "",
					refreshToken: account.refreshToken ?? undefined,
					idToken: account.idToken ?? undefined,
				},
				{
					linkTo: context.session ? { id: context.session.user.id } : undefined,
				},
			);
			// Refuse the link.
			if (!resolved || resolved.id !== account.userId) return false;
			return earlier;
		};
	}

	/**
	 * Binds a `nestPasswordHasher()` placeholder to the injected hasher, and
	 * rehashes on sign-in: it is the only place the plaintext is available,
	 * as the Nest docs recommend.
	 */
	private wirePassword(): void {
		const auth = this.options.auth.options as Options;
		const password = auth.emailAndPassword?.password as
			| (BetterAuthPassword & Partial<NestPasswordHasher>)
			| undefined;
		const bind = password?.[BIND_PASSWORD_HASHER];
		if (bind) {
			if (!this.hasher)
				throw new Error(
					"nestPasswordHasher() needs PasswordHasher: import AuthenticationModule from '@nestjs/authentication'.",
				);
			bind(this.hasher, {});
		}

		const hasher = password?.[PASSWORD_HASHER];
		if (!hasher) return;

		const hooks = auth.hooks as Options | undefined;
		if (typeof hooks !== "object" || hooks === null) {
			this.logger.debug(
				"Add 'hooks: {}' to your betterAuth(...) options to rehash outdated password hashes on sign-in.",
			);
			return;
		}

		const original = hooks.after;
		hooks.after = createAuthMiddleware(async (ctx) => {
			// An `after` hook's return value replaces the endpoint's response.
			const result = original ? await original(ctx) : undefined;
			if (ctx.path !== "/sign-in/email") return result;

			const userId = ctx.context.newSession?.user.id;
			const plaintext = (ctx.body as { password?: unknown } | undefined)
				?.password;
			if (!userId || typeof plaintext !== "string") return result;

			// The user is already signed in: an outdated hash that can't be
			// upgraded now must not fail the request.
			try {
				await rehash(ctx.context.internalAdapter, userId, plaintext);
			} catch (error) {
				this.logger.warn(
					`Could not rehash the password of user ${userId}: ${(error as Error).message}`,
				);
			}
			return result;
		});

		const rehash = async (
			adapter: Options,
			userId: string,
			plaintext: string,
		) => {
			const accounts = await adapter.findAccounts(userId);
			const credential = accounts.find(
				(a: Options) => a.providerId === "credential",
			);
			const encoded = credential?.password;
			if (!encoded) return;
			if (encoded.startsWith("$scrypt$") && !hasher.needsRehash(encoded))
				return;

			await adapter.updatePassword(userId, await hasher.hash(plaintext));
		};
	}

	private require(
		auth: Options,
		key: string,
		handler: string,
		example: string,
	): Options {
		const parent = auth[key];
		if (typeof parent !== "object" || parent === null)
			throw new Error(
				`Detected a ${handler} but Better Auth '${key}' is not configured. Add '${example}' to your betterAuth(...) options.`,
			);
		return parent;
	}
}
