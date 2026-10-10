import { Router } from "express";
import { jwksController } from "./jwks.controller";

export const jwksRoute = Router();

// Endpoint công khai theo chuẩn IETF RFC 7517
jwksRoute.get("/.well-known/jwks.json", jwksController.getJwks);
jwksRoute.get("/jwks.json", jwksController.getJwks);
