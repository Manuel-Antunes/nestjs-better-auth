import request from "supertest";
import { Test } from "@nestjs/testing";
import { Module } from "@nestjs/common";
import { AuthenticationModule } from "@nestjs/authentication";
import { AuthModule } from "../../src/index.ts";
import {
	createNestAuth,
	createNestModeApp,
	signUp,
	verifyEmail,
} from "../shared/nest-mode.ts";
import { createTestNestApplication } from "../shared/test-utils.ts";
import { twoFactor } from "better-auth/plugins/two-factor";

describe("nest authentication e2e (authentication: 'nestjs')", () => {
	let setup: Awaited<ReturnType<typeof createNestModeApp>>;

	beforeAll(async () => {
		setup = await createNestModeApp({ auth: createNestAuth() });
	});

	afterAll(async () => {
		await setup.app.close();
	});

	const server = () => setup.app.getHttpServer();

	it("rejects a protected route without credentials", async () => {
		await request(server()).get("/nest/protected").expect(401);
	});

	it("rejects an invalid bearer token", async () => {
		await request(server())
			.get("/nest/protected")
			.set("Authorization", "Bearer invalid-token")
			.expect(401);
	});

	it("resolves the Better Auth user and session through @CurrentUser/@CurrentSession", async () => {
		const { token, user } = await signUp(setup.auth);

		const response = await request(server())
			.get("/nest/protected")
			.set("Authorization", `Bearer ${token}`)
			.expect(200);

		expect(response.body.user).toMatchObject({
			id: user.id,
			email: user.email,
		});
		expect(response.body.session).toMatchObject({ userId: user.id });
	});

	it("resolves the user from the session cookie", async () => {
		const email = `cookie-${Date.now()}@example.com`;
		const signUpResponse = await request(server())
			.post("/api/auth/sign-up/email")
			.send({ name: "Cookie", email, password: "password-123456" })
			.expect(200);
		const cookies = signUpResponse.headers["set-cookie"];

		const response = await request(server())
			.get("/nest/protected")
			.set("Cookie", cookies)
			.expect(200);

		expect(response.body.user.email).toBe(email);
	});

	it("keeps Better Auth's own routes outside the guard", async () => {
		await request(server()).get("/api/auth/ok").expect(200);
	});

	it("reads the user from AuthenticationContext in a controller", async () => {
		const { token, user } = await signUp(setup.auth);

		const response = await request(server())
			.get("/nest/context")
			.set("Authorization", `Bearer ${token}`)
			.expect(200);

		expect(response.body.id).toBe(user.id);
	});

	describe("@Public() and its AllowAnonymous alias", () => {
		it("allows anonymous access", async () => {
			await request(server()).get("/nest/public").expect(200);
			await request(server()).get("/nest/allow-anonymous").expect(200);
		});

		it("does not run providers, so @CurrentUser() is null", async () => {
			const { token } = await signUp(setup.auth);

			const response = await request(server())
				.get("/nest/public")
				.set("Authorization", `Bearer ${token}`)
				.expect(200);

			expect(response.body.user).toBeNull();
		});
	});

	describe("optional authentication", () => {
		it.each(["optional", "optional-nest"])(
			"/%s lets anonymous callers through",
			async (route) => {
				const response = await request(server())
					.get(`/nest/${route}`)
					.expect(200);

				expect(response.body.authenticated).toBe(false);
			},
		);

		it.each(["optional", "optional-nest"])(
			"/%s resolves the user when credentials are present",
			async (route) => {
				const { token } = await signUp(setup.auth);

				const response = await request(server())
					.get(`/nest/${route}`)
					.set("Authorization", `Bearer ${token}`)
					.expect(200);

				expect(response.body.authenticated).toBe(true);
			},
		);
	});

	describe("@Session() alias", () => {
		it("returns Better Auth's { user, session }", async () => {
			const { token, user } = await signUp(setup.auth);

			const response = await request(server())
				.get("/nest/session-alias")
				.set("Authorization", `Bearer ${token}`)
				.expect(200);

			expect(response.body).toEqual({ userId: user.id, hasSession: true });
		});

		it("returns null for anonymous callers on optional routes", async () => {
			const response = await request(server())
				.get("/nest/session-alias-optional")
				.expect(200);

			expect(response.body.authenticated).toBe(false);
		});
	});

	describe("@Authenticate({ verifiedEmail })", () => {
		it("answers 403 email_unverified while the email is unverified", async () => {
			const { token } = await signUp(setup.auth);

			const response = await request(server())
				.get("/nest/verified")
				.set("Authorization", `Bearer ${token}`)
				.expect(403);

			expect(response.body.error).toBe("email_unverified");
		});

		it("allows a verified email", async () => {
			const { token, user } = await signUp(setup.auth);
			await verifyEmail(setup.auth, user.id);

			const response = await request(server())
				.get("/nest/verified")
				.set("Authorization", `Bearer ${token}`)
				.expect(200);

			expect(response.body.email).toBe(user.email);
		});
	});

	describe("@Authenticate({ providers })", () => {
		it("accepts the session on a BetterAuthSessionProvider route", async () => {
			const { token } = await signUp(setup.auth);

			await request(server())
				.get("/nest/session-only")
				.set("Authorization", `Bearer ${token}`)
				.expect(200);
		});

		it("refuses a session on an ApiKeyProvider route", async () => {
			const { token } = await signUp(setup.auth);

			await request(server())
				.get("/nest/api-key-only")
				.set("Authorization", `Bearer ${token}`)
				.expect(401);
		});
	});

	it("does not satisfy @Authenticate({ mfa: true }) without two-factor", async () => {
		const { token } = await signUp(setup.auth);

		const response = await request(server())
			.get("/nest/mfa")
			.set("Authorization", `Bearer ${token}`)
			.expect(401);

		expect(response.body.error).toBe("mfa_required");
	});
});

describe("nest authentication e2e: MFA mapping", () => {
	it("does not treat two-factor enrollment as a verified second factor", async () => {
		const auth = createNestAuth({
			appName: "test",
			plugins: [twoFactor()],
		});
		const { app } = await createNestModeApp({ auth });

		try {
			const { token, user } = await signUp(auth);
			const ctx = await auth.$context;
			await ctx.internalAdapter.updateUser(user.id, {
				twoFactorEnabled: true,
			});

			const response = await request(app.getHttpServer())
				.get("/nest/mfa")
				.set("Authorization", `Bearer ${token}`)
				.expect(401);

			expect(response.body.error).toBe("mfa_required");
		} finally {
			await app.close();
		}
	});

	it("maps enrolled users to a verified second factor with trustTwoFactorEnrollment", async () => {
		const auth = createNestAuth({
			appName: "test",
			plugins: [twoFactor()],
		});
		const { app } = await createNestModeApp({
			auth,
			authModule: AuthModule.forRoot({
				auth,
				authentication: "nestjs",
				session: { trustTwoFactorEnrollment: true },
			}),
		});

		try {
			const { token, user } = await signUp(auth);
			const ctx = await auth.$context;
			await ctx.internalAdapter.updateUser(user.id, {
				twoFactorEnabled: true,
			});

			await request(app.getHttpServer())
				.get("/nest/mfa")
				.set("Authorization", `Bearer ${token}`)
				.expect(200);
		} finally {
			await app.close();
		}
	});
});

describe("nest authentication e2e: module wiring", () => {
	it("works with forRootAsync()", async () => {
		const auth = createNestAuth();
		const { app } = await createNestModeApp({
			auth,
			authModule: AuthModule.forRootAsync({
				authentication: "nestjs",
				useFactory: () => ({ auth }),
			}),
		});

		try {
			const { token } = await signUp(auth);
			await request(app.getHttpServer())
				.get("/nest/protected")
				.set("Authorization", `Bearer ${token}`)
				.expect(200);
			await request(app.getHttpServer()).get("/nest/protected").expect(401);
		} finally {
			await app.close();
		}
	});

	it("fails at startup when BetterAuthAuthenticationModule is not imported", async () => {
		const auth = createNestAuth();

		@Module({
			imports: [
				AuthenticationModule.forRoot(),
				AuthModule.forRoot({ auth, authentication: "nestjs" }),
			],
		})
		class AppModule {}

		const moduleRef = await Test.createTestingModule({
			imports: [AppModule],
		}).compile();

		await expect(createTestNestApplication(moduleRef)).rejects.toThrow(
			/BetterAuthAuthenticationModule is not imported/,
		);
	});

	it("keeps the legacy guard by default", async () => {
		const auth = createNestAuth();

		@Module({
			imports: [AuthModule.forRoot({ auth })],
			controllers: [],
		})
		class AppModule {}

		const moduleRef = await Test.createTestingModule({
			imports: [AppModule],
		}).compile();
		const app = await createTestNestApplication(moduleRef);
		await app.close();
	});
});
