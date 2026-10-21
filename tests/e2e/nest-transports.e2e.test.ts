import request from "supertest";
import { io as ioc, type Socket } from "socket.io-client";
import {
	NestAuthController,
	NestAuthGateway,
	NestAuthResolver,
	createNestAuth,
	createNestModeApp,
	signUp,
} from "../shared/nest-mode.ts";

const waitFor = (socket: Socket, event: string) =>
	new Promise<unknown>((resolve) => socket.once(event, resolve));

describe("nest authentication e2e: GraphQL and WebSockets", () => {
	let setup: Awaited<ReturnType<typeof createNestModeApp>>;
	let port: number;
	let socket: Socket | undefined;

	beforeAll(async () => {
		setup = await createNestModeApp({
			auth: createNestAuth(),
			controllers: [NestAuthController],
			providers: [NestAuthResolver, NestAuthGateway],
			withGraphql: true,
		});
		await setup.app.listen(0);
		port = setup.app.getHttpServer().address()?.port;
	});

	afterEach(() => {
		socket?.disconnect();
		socket = undefined;
	});

	afterAll(async () => {
		await setup.app.close();
	});

	const graphql = (query: string, token?: string) => {
		const req = request(setup.app.getHttpServer())
			.post("/graphql")
			.set("Content-Type", "application/json");
		if (token) req.set("Authorization", `Bearer ${token}`);
		return req.send({ query });
	};

	describe("graphql", () => {
		it("resolves a public query without credentials", async () => {
			const response = await graphql("{ publicHello }").expect(200);
			expect(response.body.data.publicHello).toBe("ok");
		});

		it("answers UNAUTHENTICATED for a protected query", async () => {
			const response = await graphql("{ protectedUserId }").expect(200);
			expect(response.body.errors?.[0]?.extensions?.code).toBe(
				"UNAUTHENTICATED",
			);
		});

		it("resolves a protected query with a session", async () => {
			const { token, user } = await signUp(setup.auth);
			const response = await graphql(
				"{ protectedUserId }",
				token ?? undefined,
			).expect(200);
			expect(response.body.data.protectedUserId).toBe(user.id);
		});
	});

	describe("websockets", () => {
		const connect = async (token?: string) => {
			socket = ioc(`http://localhost:${port}/test`, {
				path: "/ws",
				...(token && { extraHeaders: { Authorization: `Bearer ${token}` } }),
			});
			await waitFor(socket, "connect");
			return socket;
		};

		it("allows an anonymous message on a public event", async () => {
			const client = await connect();
			const response = waitFor(client, "anonymous");
			client.emit("anonymous");
			expect(await response).toBe("hello");
		});

		it("rejects an unauthenticated message on a protected event", async () => {
			const client = await connect();
			const response = waitFor(client, "exception");
			client.emit("protected");
			expect(await response).toBeDefined();
		});

		it("authenticates a message with the handshake's bearer token", async () => {
			const { token, user } = await signUp(setup.auth);
			const client = await connect(token ?? undefined);
			const response = waitFor(client, "protected");
			client.emit("protected");
			expect(await response).toBe(user.name);
		});
	});
});
