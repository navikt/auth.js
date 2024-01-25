import { createRemoteJWKSet, jwtVerify } from "jose";
import { Issuer } from "openid-client";

type VerificationResult =
  | {
      valid: false;
      error: "token verification failed";
    }
  | {
      valid: true;
    };

export const verifyJwt = async (
  token: string,
  {
    expectedAudience,
    expectedIssuer,
  }: { expectedAudience: string; expectedIssuer: string }
): Promise<VerificationResult> => {
  const wellKnownUrl = process.env.TOKEN_X_WELL_KNOWN_URL!;
  const tokenXIssuer = await Issuer.discover(wellKnownUrl);
  const remoteJWKS = await createRemoteJWKSet(
    new URL(tokenXIssuer.jwks_uri as string)
  );
  try {
    await jwtVerify(token, remoteJWKS, {
      issuer: expectedIssuer ?? tokenXIssuer.metadata.issuer,
      audience:
        expectedAudience ??
        `${process.env.NAIS_CLUSTER_NAME}:${process.env.NAIS_NAMESPACE}:${process.env.NAIS_APP_NAME}`,
    });
    return {
      valid: true,
    };
  } catch (err) {
    return {
      valid: false,
      error: "token verification failed",
    };
  }
};
