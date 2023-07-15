import { Forge4FlowClient } from "@forge4flow/forge4flow-node";
import { Middleware } from "next-api-route-middleware";
import Cookies from "cookies";

/*
 * withSessionPermission returns a Nextjs middleware function
 * which will check that the logged in user has the
 * required permission before executing the route handler.
 */
const withSessionPermission = (permissionId: string): Middleware => {
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

export default withSessionPermission;
