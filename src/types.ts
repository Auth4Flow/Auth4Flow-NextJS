import { NextApiRequest } from "next";

export type NextApiRequestWithUser = NextApiRequest & { userId: string };
