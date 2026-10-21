import request from "supertest";
import { jwt } from "better-auth/plugins/jwt";
import { apiKey } from "@better-auth/api-key";
import {
	createNestAuth,
	createNestModeApp,
	signUp,
} from "../shared/nest-mode.ts";

describe("nest authentication e2e: api key", () => {
	let setup: Awaited<ReturnType<typeof createNestModeApp>>;

	beforeAll(async () => {
		setup = await createNestModeApp({
			auth: createNestAuth({ plugins: [apiKey()] }),
		});
	});

	afterAll(async () => {
		await setup.app.close();
	});

	const server = () => setup.app.getHttpServer();

	// biome-ignore lint/suspicious/noExplicitAny: the api-key endpoints are not typed on the generic auth instance
	const api = () => setup.auth.api as any;

	it("accepts a valid key and exposes its id as the session", async () => {
		const { user } = await signUp(setup.auth);
		const created = await api().createApiKey({
			body: { userId: user.id, name: "ci" },
		});

		const response = await request(server())
			.get("/nest/protected")
			.set("x-api-key", created.key)
			.expect(200);

		expect(response.body.user.id).toBe(user.id);
		expect(response.body.session).toMatchObject({
			method: "api-key",
			keyId: created.id,
		});
	});

	it("rejects an unknown key with the key challenge", async () => {
		const response = await request(server())
			.get("/nest/protected")
			.set("x-api-key", "not-a-real-key")
			.expect(401);

		expect(response.headers["www-authenticate"]).toContain("ApiKey");
	});

	it("rejects a revoked key", async () => {
		const { user } = await signUp(setup.auth);
		const created = await api().createApiKey({
			body: { userId: user.id, name: "revoked" },
		});
		await api().deleteApiKey({
			body: { keyId: created.id },
			headers: new Headers({
				Authorization: `Bearer ${(await signInToken(user.email)) ?? ""}`,
			}),
		});

		await request(server())
			.get("/nest/protected")
			.set("x-api-key", created.key)
			.expect(401);
	});

	it("rejects an expired key", async () => {
		const { user } = await signUp(setup.auth);
		const created = await api().createApiKey({
			body: { userId: user.id, name: "expired", expiresIn: 60 * 60 * 24 },
		});
		const ctx = await setup.auth.$context;
		await ctx.adapter.update({
			model: "apikey",
			where: [{ field: "id", value: created.id }],
			update: { expiresAt: new Date(Date.now() - 1000) },
		});

		await request(server())
			.get("/nest/protected")
			.set("x-api-key", created.key)
			.expect(401);
	});

	it("is covered by @Authenticate({ providers: [ApiKeyProvider] })", async () => {
		const { user, token } = await signUp(setup.auth);
		const created = await api().createApiKey({
			body: { userId: user.id, name: "scoped" },
		});

		await request(server())
			.get("/nest/api-key-only")
			.set("x-api-key", created.key)
			.expect(200);
		await request(server())
			.get("/nest/api-key-only")
			.set("Authorization", `Bearer ${token}`)
			.expect(401);
	});

	it("never satisfies @Authenticate({ mfa: true })", async () => {
		const { user } = await signUp(setup.auth);
		const created = await api().createApiKey({
			body: { userId: user.id, name: "mfa" },
		});

		await request(server())
			.get("/nest/mfa")
			.set("x-api-key", created.key)
			.expect(401);
	});

	/** A bearer token for an existing user. */
	async function signInToken(email: string) {
		const result = await setup.auth.api.signInEmail({
			body: { email, password: "password-123456" },
		});
		return result.token;
	}
});

describe("nest authentication e2e: jwt", () => {
	let setup: Awaited<ReturnType<typeof createNestModeApp>>;

	beforeAll(async () => {
		setup = await createNestModeApp({
			auth: createNestAuth({
				baseURL: "http://localhost:3000",
				plugins: [jwt()],
			}),
		});
	});

	afterAll(async () => {
		await setup.app.close();
	});

	const server = () => setup.app.getHttpServer();

	/** A JWT issued by the `jwt()` plugin for the session behind `token`. */
	const getToken = (token: string | null): Promise<{ token: string }> =>
		// biome-ignore lint/suspicious/noExplicitAny: the jwt endpoints are not typed on the generic auth instance
		(setup.auth.api as any).getToken({
			headers: new Headers({ Authorization: `Bearer ${token}` }),
		});

	it("authenticates a JWT issued by Better Auth", async () => {
		const { token, user } = await signUp(setup.auth);
		const { token: jwtToken } = await getToken(token);

		const response = await request(server())
			.get("/nest/protected")
			.set("Authorization", `Bearer ${jwtToken}`)
			.expect(200);

		expect(response.body.user.id).toBe(user.id);
		expect(response.body.session).toMatchObject({ sub: user.id });
	});

	it("rejects a tampered JWT", async () => {
		const { token } = await signUp(setup.auth);
		const { token: jwtToken } = await getToken(token);
		const [header, payload] = jwtToken.split(".");

		await request(server())
			.get("/nest/protected")
			.set("Authorization", `Bearer ${header}.${payload}.invalid-signature`)
			.expect(401);
	});

	it("leaves non-JWT bearer tokens to the session provider", async () => {
		const { token } = await signUp(setup.auth);

		await request(server())
			.get("/nest/protected")
			.set("Authorization", `Bearer ${token}`)
			.expect(200);
	});
});
