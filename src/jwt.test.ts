import { randomUUID } from "crypto";
import { GenericContainer, StartedTestContainer, Wait } from "testcontainers";
import { verifyJwt } from "./jwt";
import { Issuer } from "openid-client";

const validIdportenClaims = {
  client_id: "idporten-test-client-id",
  acr: "Level4",
  client_amr: "private_key_jwt",
  sub: randomUUID(),
  aud: "notfound",
  at_hash: randomUUID(),
  amr: ["BankId"],
  pid: "user-pid",
  locale: "nb",
  sid: randomUUID(),
  auth_time: Date.now(),
};

const validAzureAdClaims = {
  aud: "test-client-id",
};

const mockOauth2ServerJsonConfig = {
  interactiveLogin: true,
  httpServer: "NettyWrapper",
  tokenCallbacks: [
    {
      issuerId: "idporten",
      tokenExpiry: 3,
      requestMappings: [
        {
          requestParam: "VALID",
          match: "true",
          claims: validIdportenClaims,
        },
        {
          requestParam: "WRONG_CLIENT_ID",
          match: "true",
          claims: {
            ...validIdportenClaims,
            client_id: "some-invalid-client-id",
          },
        },
        {
          requestParam: "WRONG_ACR",
          match: "true",
          claims: {
            ...validIdportenClaims,
            acr: "Level3",
          },
        },
        {
          requestParam: "NEW_ACR",
          match: "true",
          claims: {
            ...validIdportenClaims,
            acr: "idporten-loa-high",
          },
        },
      ],
    },
    {
      issuerId: "azure",
      tokenExpiry: 3,
      requestMappings: [
        {
          requestParam: "VALID",
          match: "true",
          claims: validAzureAdClaims,
        },
        {
          requestParam: "WRONG_CLIENT_ID",
          match: "true",
          claims: { ...validAzureAdClaims, aud: "some-invalid-client-id" },
        },
      ],
    },
  ],
};

const MOCK_OAUTH_SERVER_PORT = 8080;

describe("idporten token", () => {
  let container: StartedTestContainer;

  beforeAll(async () => {
    container = await new GenericContainer(
      "ghcr.io/navikt/mock-oauth2-server:2.1.1"
    )
      .withEnvironment({
        LOG_LEVEL: "DEBUG",
        JSON_CONFIG: JSON.stringify(mockOauth2ServerJsonConfig),
      })
      .withExposedPorts(MOCK_OAUTH_SERVER_PORT)
      .withWaitStrategy(Wait.forLogMessage(/.*started server.*/))
      .start()
      .then((it) => {
        console.info(
          `Started mock-oauth2-server on http://${it.getHost()}:${it.getMappedPort(
            MOCK_OAUTH_SERVER_PORT
          )}`
        );
        return it;
      });

    process.env.TOKEN_X_WELL_KNOWN_URL = `http://localhost:${container.getMappedPort(
      MOCK_OAUTH_SERVER_PORT
    )}/default/.well-known/openid-configuration`;
  });

  it("foo", async () => {
    expect(
      await verifyJwt("foo", {
        expectedAudience: "default",
        expectedIssuer: "default",
      })
    ).toStrictEqual({
      valid: false,
      error: "token verification failed",
    });
  });

  it("works", async () => {
    const wellKnownUrl = process.env.TOKEN_X_WELL_KNOWN_URL!;
    const tokenXIssuer = await Issuer.discover(wellKnownUrl);
    const res = await fetch(tokenXIssuer.metadata.token_endpoint as string, {
      method: "POST",
      body: new URLSearchParams({
        issuerId: "issuer1",
        tokenExpiry: "120",
        requestMappings: JSON.stringify([
          {
            requestParam: "scope",
            match: "scope1",
            claims: {
              sub: "subByScope",
              aud: ["audByScope"],
            },
          },
        ]),
      }),
    });
    console.log(await res.text());
    /*
    expect(
      await verifyJwt(, {
        expectedAudience: "default",
        expectedIssuer: "default",
      })
    ).toStrictEqual({
      valid: false,
      error: "token verification failed",

    });
    */
  });
});
