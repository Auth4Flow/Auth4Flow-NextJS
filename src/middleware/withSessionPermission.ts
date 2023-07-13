import { Auth4FlowClient } from "@auth4flow/auth4flow-node";
import { NextApiRequest } from "next";
import { Middleware } from "next-api-route-middleware";
import Cookies from "cookies";

export type User = { userId: string };
export type NextApiRequestWithUser = NextApiRequest & User;

/*
 * withSessionPermission returns a Nextjs middleware function
 * which will check that the logged in user has the
 * required permission before executing the route handler.
 */
const withSessionPermission = (permissionId: string): Middleware => {
  const auth4Flow = new Auth4FlowClient({
    endpoint: process.env.AUTH4FLOW_BASE_URL,
    apiKey: process.env.AUTH4FLOW_API_KEY,
  });

  return async function (req, res, next) {
    const sessionId = new Cookies(req, res).get("__auth4FlowSessionToken");
    console.log(sessionId);
    if (sessionId) {
      const userId = await auth4Flow.Session.verifySession(sessionId);

      if (
        !(await auth4Flow.Authorization.hasPermission({
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

export default withSessionPermission;
