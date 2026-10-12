import express from "express";
import cors from "cors";
import helmet from "helmet";
import morgan from "morgan";
import swaggerUi from "swagger-ui-express";
import cookieParser from "cookie-parser";
import {
  errorMiddleware,
  notFoundMiddleware,
} from "./middlewares/error.middleware";
import routes from "./routes";
import securityTxtRoute from "./modules/security-txt/security-txt.route";
import { jwksRoute } from "./modules/jwks/jwks.route";
import { swaggerSpec, swaggerOptions } from "./config/swagger.config";
import { rateLimitMiddleware } from "./middlewares/rate-limit.middleware";
import { requestIdMiddleware } from "./middlewares/request-id.middleware";
import { envConfig } from "./config/env.config";

const app = express();

app.set("trust proxy", envConfig.trustProxy);

app.use(requestIdMiddleware);
app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'", "'unsafe-inline'"],
        styleSrc: ["'self'", "'unsafe-inline'"],
        imgSrc: ["'self'", "data:", "https:"],
      },
    },
  }),
);

const corsOptions: cors.CorsOptions = {
  origin: (origin, callback) => {
    const allowed = envConfig.cors.allowedOrigins.map((o) =>
      o.replace(/\/+$/, ""),
    );
    if (!origin) {
      callback(null, true);
      return;
    }
    const cleanOrigin = origin.replace(/\/+$/, "");
    if (allowed.includes("*")) {
      if (envConfig.nodeEnv !== "production") {
        callback(null, true);
        return;
      }
      // Chặn wildcard '*' trên production
      console.error(
        "[CORS] CORS_ALLOWED_ORIGINS=* is not permitted in production. Configure specific origins.",
      );
      callback(null, false);
      return;
    }
    if (allowed.includes(cleanOrigin)) {
      callback(null, true);
    } else {
      callback(null, false);
    }
  },
  credentials: true,
};
app.use(cors(corsOptions));
app.use(morgan(envConfig.nodeEnv === "production" ? "combined" : "dev"));
app.use(express.json({ limit: "2mb" }));
app.use(express.urlencoded({ extended: true, limit: "2mb" }));
app.use(cookieParser());

app.use(
  "/api/docs",
  swaggerUi.serve,
  swaggerUi.setup(swaggerSpec, swaggerOptions),
);

app.use(securityTxtRoute);
app.use(rateLimitMiddleware, jwksRoute);
app.use("/api/v1", rateLimitMiddleware, routes);

app.use(notFoundMiddleware);
app.use(errorMiddleware);

export default app;
