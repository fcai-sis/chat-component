import cors from "cors";
import morgan from "morgan";
import helmet from "helmet";
import jwt from "jsonwebtoken";
import { createServer } from "http";
import compression from "compression";
import express, { NextFunction, Request, Response } from "express";

import router from "./router";
import { isDev } from "./env";
import logger from "./core/logger";
import { Server } from "socket.io";
import { TokenPayload } from "@fcai-sis/shared-middlewares";

// Create Express server
const app = express();
export const httpServer = createServer(app);

// Initialize the context object
app.use((req: Request, _: Response, next: NextFunction) => {
  req.context = {};
  next();
});

// Configure HTTP request logger middleware
app.use(
  morgan("combined", {
    stream: { write: (message) => logger.http(message) },
    skip: () => isDev,
  })
);

// Use helmet to secure HTTP headers
// https://expressjs.com/en/advanced/best-practice-security.html#use-helmet
app.use(helmet());

// Disable the `X-Powered-By` HTTP header for security
// https://expressjs.com/en/advanced/best-practice-security.html#reduce-fingerprinting
app.disable("x-powered-by");

// Use compression middleware to compress HTTP responses
// https://stackoverflow.com/a/58813283/14174934
app.use(compression());

// Enable CORS
// https://stackoverflow.com/a/61988727/14174934
app.use(cors());

// Parse JSON and url-encoded query
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Mount API routes
app.use("/", router());

// TODO: Custom 404 handler
app.use((req: Request, res: Response, next: NextFunction) => {
  res.status(404).json({ message: "Not found" });
});

// TODO: Custom error handler
app.use((err: Error, req: Request, res: Response, next: NextFunction) => {
  logger.error(err.stack);
  res.status(500).json({ message: "Something broke on our end" });
});


// Socket.io
const io = new Server(httpServer, {
  cors: {
    origin: "*",
  },
});

io.use((socket, next) => {
  const token = socket.handshake.auth.token;

  if (!token) {
    console.error("No token provided");
    return next(new Error("Authentication error"));
  }

  // Verify token
  try {
    // Verify JWT token and decode payload
    const decodedToken = jwt.verify(token, process.env.JWT_SECRET as string) as TokenPayload;

    console.log("Decoded token: ", decodedToken);

    const { userId } = decodedToken;

    // TODO: Check if the user exists in the database

    // Attach the decoded payload to the socket
    socket.data.userId = userId;

    next();
  } catch (err) {
    console.error("Error verifying token: ", err);

    return next(new Error("Authentication error"));
  }
});

io.on("connection", (socket) => {
  logger.info(`Socket connected: ${socket.id}`);

  socket.on("disconnect", () => {
    logger.info(`Socket disconnected: ${socket.id}`);
  });
});

export default app;
