import { Forge4FlowClient } from "@forge4flow/forge4flow-node";
import { Middleware, use } from "next-api-route-middleware";
import Cookies from "cookies";
import { NextApiRequest } from "next";

/*
 * withSessionPermission returns a Nextjs middleware handler
 * which will check that the logged in user has the
 * required permission before executing the route handler.
 */
export const sessionPermissionMiddleware = (
  permissionId: string
): Middleware => {
  const forge4Flow = new Forge4FlowClient({
    endpoint: process.env.AUTH4FLOW_BASE_URL,
    apiKey: process.env.AUTH4FLOW_API_KEY,
  });

  return async function (req, res, next) {
    const sessionId = new Cookies(req, res).get("__forge4FlowSessionToken");
    console.log(sessionId);
    if (sessionId) {
      const userId = await forge4Flow.Session.verifySession(sessionId);

      if (
        !(await forge4Flow.Authorization.hasPermission({
          permissionId: permissionId,
          subject: {
            objectType: "user",
            objectId: userId,
          },
        }))
      ) {
        res.status(403).json({ success: false, message: "access denied" });
        return;
      }

      await next();

      return;
    }

    res.status(401).send({ message: "Invalid auth cookie." });
  };
};

export function withSessionPermission<RequestT extends NextApiRequest>(
  ...middlewaresOrPermissions: (Middleware<RequestT> | string)[]
): Middleware<RequestT> {
  const middlewares: Middleware<RequestT>[] = [];
  let permissionId: string | undefined;

  for (const item of middlewaresOrPermissions) {
    if (typeof item === "string") {
      middlewares.push(sessionPermissionMiddleware(item));
      permissionId = item;
    } else {
      middlewares.push(item);
    }
  }

  if (!permissionId) {
    throw new Error("Permission ID is missing.");
  }

  return use(...middlewares);
}
