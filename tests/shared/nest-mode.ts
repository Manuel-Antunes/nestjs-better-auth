import "reflect-metadata";
import { Test } from "@nestjs/testing";
import {
	Controller,
	Get,
	Module,
	type DynamicModule,
	type INestApplication,
	type Provider,
	type Type,
} from "@nestjs/common";
import { ApolloDriver, type ApolloDriverConfig } from "@nestjs/apollo";
import { GraphQLModule, Query, Resolver } from "@nestjs/graphql";
import { SubscribeMessage, WebSocketGateway } from "@nestjs/websockets";
import {
	Authenticate,
	AuthenticationContext,
	AuthenticationModule,
	type AuthenticationModuleOptions,
	CurrentSession,
	CurrentUser,
	Public,
} from "@nestjs/authentication";
import { AuthorizationModule } from "@nestjs/authorization";
import { ApiKeyProvider } from "@nestjs/authentication";
import type { Request, Response } from "express";
import { bearer } from "better-auth/plugins/bearer";
import { betterAuth } from "better-auth";
import { AuthModule } from "../../src/index.ts";
import {
	AllowAnonymous,
	BetterAuthAuthenticationModule,
	BetterAuthSessionProvider,
	OptionalAuth,
	Session,
} from "../../src/authentication/index.ts";
import { createTestNestApplication } from "./test-utils.ts";

type BetterAuthOptions = Parameters<typeof betterAuth>[0];

/**
 * Cheap stand-in for scrypt: most suites create dozens of users and don't
 * test passwords, and hashing them for real makes the suite CPU bound (and
 * flaky on small CI machines). Suites about hashing pass their own
 * `emailAndPassword`.
 */
const fastPassword = {
	hash: async (password: string) => `plain:${password}`,
	verify: async ({ hash, password }: { hash: string; password: string }) =>
		hash === `plain:${password}`,
};

/** A Better Auth instance with the bearer plugin, plus any `plugins` of `options`. */
export function createNestAuth(options?: Partial<BetterAuthOptions>) {
	return betterAuth({
		basePath: "/api/auth",
		emailAndPassword: { enabled: true, password: fastPassword },
		...options,
		plugins: [bearer(), ...(options?.plugins ?? [])],
	});
}

/** Routes exercising `@nestjs/authentication`'s decorators and this library's aliases. */
@Controller("nest")
export class NestAuthController {
	constructor(private readonly context: AuthenticationContext) {}

	@Get("protected")
	protected(
		@CurrentUser() user: { id: string },
		@CurrentSession() session: { id?: string; method?: string; keyId?: string },
	) {
		return { user, session };
	}

	@AllowAnonymous()
	@Get("allow-anonymous")
	allowAnonymous() {
		return { ok: true };
	}

	@Public()
	@Get("public")
	public(@CurrentUser() user: unknown) {
		return { ok: true, user };
	}

	@OptionalAuth()
	@Get("optional")
	optional(@CurrentUser() user: { id: string } | null) {
		return { authenticated: !!user, userId: user?.id ?? null };
	}

	@Authenticate({ optional: true })
	@Get("optional-nest")
	optionalNest(@CurrentUser() user: { id: string } | null) {
		return { authenticated: !!user };
	}

	@Authenticate({ verifiedEmail: true })
	@Get("verified")
	verified(@CurrentUser("email") email: string) {
		return { email };
	}

	@Authenticate({ mfa: true })
	@Get("mfa")
	mfa() {
		return { ok: true };
	}

	@Authenticate({ providers: [BetterAuthSessionProvider] })
	@Get("session-only")
	sessionOnly(@CurrentUser("id") id: string) {
		return { id };
	}

	@Authenticate({ providers: [ApiKeyProvider] })
	@Get("api-key-only")
	apiKeyOnly(@CurrentUser("id") id: string) {
		return { id };
	}

	@Get("context")
	contextUser() {
		return { id: this.context.requireUser().id };
	}

	@Get("session-alias")
	sessionAlias(@Session() session: { user: { id: string }; session: unknown }) {
		return { userId: session.user.id, hasSession: !!session.session };
	}

	@OptionalAuth()
	@Get("session-alias-optional")
	sessionAliasOptional(@Session() session: { user: { id: string } } | null) {
		return { authenticated: !!session };
	}
}

/** GraphQL resolver for the `authentication: 'nestjs'` tests. */
@Resolver()
export class NestAuthResolver {
	@AllowAnonymous()
	@Query(() => String)
	publicHello(): string {
		return "ok";
	}

	@Query(() => String)
	protectedUserId(@CurrentUser("id") id: string): string {
		return id;
	}
}

/** WebSocket gateway for the `authentication: 'nestjs'` tests. */
@WebSocketGateway({ path: "/ws", namespace: "test", cors: { origin: "*" } })
export class NestAuthGateway {
	@AllowAnonymous()
	@SubscribeMessage("anonymous")
	anonymous() {
		return { event: "anonymous", data: "hello" };
	}

	@SubscribeMessage("protected")
	protectedMessage(@CurrentUser("name") name: string) {
		return { event: "protected", data: name };
	}
}

export interface NestModeAppOptions {
	auth: ReturnType<typeof createNestAuth>;
	controllers?: Type<unknown>[];
	providers?: Provider[];
	/** Import `AuthorizationModule` (deny-by-default). */
	authorization?: boolean;
	authentication?: AuthenticationModuleOptions;
	authModule?: DynamicModule;
	imports?: DynamicModule[] | Type<unknown>[];
	withGraphql?: boolean;
}

/** Builds an app with `AuthenticationModule`, `AuthModule` in `'nestjs'` mode and `BetterAuthAuthenticationModule`. */
export async function createNestModeApp(options: NestModeAppOptions) {
	const { auth } = options;

	@Module({
		imports: [
			AuthenticationModule.forRoot(options.authentication ?? {}),
			...(options.authorization ? [AuthorizationModule.forRoot()] : []),
			options.authModule ??
				AuthModule.forRoot({ auth, authentication: "nestjs" }),
			BetterAuthAuthenticationModule,
			...(options.withGraphql
				? [
						GraphQLModule.forRoot<ApolloDriverConfig>({
							driver: ApolloDriver,
							autoSchemaFile: true,
							path: "/graphql",
							context: ({ req, res }: { req: Request; res: Response }) => ({
								req,
								res,
							}),
						}),
					]
				: []),
			...((options.imports ?? []) as DynamicModule[]),
		],
		controllers: options.controllers ?? [NestAuthController],
		providers: options.providers ?? [],
	})
	class AppModule {}

	const moduleRef = await Test.createTestingModule({
		imports: [AppModule],
	}).compile();
	const app: INestApplication = await createTestNestApplication(moduleRef);
	// Listen once, on the wildcard address like the other suites: for a server
	// that isn't listening, supertest calls listen(0) and close() around every
	// request, and that churn of ephemeral ports makes long suites flaky. A
	// specific address (127.0.0.1) would not do: on macOS it can share a port
	// with another process's wildcard listener and steal its connections.
	await app.listen(0);

	return { app, auth, moduleRef };
}

let counter = 0;
/** An email address no earlier test used. */
export const uniqueEmail = () => `user-${Date.now()}-${counter++}@example.com`;

/** Signs up a user with a fresh email, returning Better Auth's result (with the bearer token). */
export async function signUp(auth: ReturnType<typeof createNestAuth>) {
	return auth.api.signUpEmail({
		body: {
			name: "Test User",
			email: uniqueEmail(),
			password: "password-123456",
		},
	});
}

/** Marks the user's email as verified. */
export async function verifyEmail(
	auth: ReturnType<typeof createNestAuth>,
	userId: string,
) {
	const ctx = await auth.$context;
	await ctx.internalAdapter.updateUser(userId, { emailVerified: true });
}
