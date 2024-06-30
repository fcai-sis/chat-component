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
import { Server, Socket } from "socket.io";
import { TokenPayload } from "@fcai-sis/shared-middlewares";
import {
  AdminModel,
  ChatModel,
  EmployeeModel,
  InstructorModel,
  RoleEnum,
  RoleEnumType,
  StudentModel,
  TeachingAssistantModel,
  UserModel,
} from "@fcai-sis/shared-models";

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

io.use(async (socket, next) => {
  const token = socket.handshake.auth.token;

  if (!token) {
    console.error("No token provided");
    return next(new Error("Authentication error"));
  }

  // Verify token
  try {
    // Verify JWT token and decode payload
    const decodedToken = jwt.verify(
      token,
      process.env.JWT_SECRET as string
    ) as TokenPayload;

    const { userId } = decodedToken;

    const user = await UserModel.findById(userId);

    // Attach the decoded payload to the socket
    socket.data.userId = userId;

    next();
  } catch (err) {
    console.error("Error verifying token: ", err);

    return next(new Error("Authentication error"));
  }
});

function getModelFromRole(role: RoleEnumType) {
  switch (role) {
    case RoleEnum[0]:
      return AdminModel;
    case RoleEnum[1]:
      return StudentModel;
    case RoleEnum[2]:
      return EmployeeModel;
    case RoleEnum[3]:
      return InstructorModel;
    case RoleEnum[4]:
      return TeachingAssistantModel;
    default:
      throw new Error("Invalid role");
  }
}

const socketsByUserId = new Map<string, Socket>();

io.on("connection", async (socket) => {
  logger.info(`Socket connected: ${socket.id}`);

  const userId = socket.data.userId;
  socketsByUserId.set(userId, socket);

  const myChats = await ChatModel.find({
    $or: [{ user1: userId }, { user2: userId }],
  });

  console.log("My chats: ", myChats);

  for (const chat of myChats) await socket.join(chat._id.toString());

  socket.rooms.forEach((room) => {
    console.log(`Socket ${socket.id} is in room ${room}`);
  });

  socket.on("message", async (data) => {
    const { message, to } = data;
    console.log("Received message: ", data);

    const [myUser, targetUser] = await Promise.all([
      UserModel.findById(userId),
      UserModel.findById(to),
    ]);

    if (!myUser || !targetUser) {
      console.error("Invalid user ID");
      return;
    }

    console.log("User ID: ", userId);

    const [me, target] = await Promise.all([
      getModelFromRole(myUser.role).findOne({ user: userId }),
      getModelFromRole(targetUser.role).findOne({ user: to }),
    ]);

    console.log(me, target);

    const newMessage = {
      message,
      sender: userId,
      sentAt: new Date(),
    };

    const messageToEmit = {
      ...newMessage,
      from: {
        user: userId,
        fullName: me.fullName,
        role: myUser.role,
      },
      to: {
        user: to,
        fullName: target.fullName,
        role: targetUser.role,
      },
    };

    const targetChat = await ChatModel.findOne({
      $or: [
        { user1: userId, user2: to },
        { user1: to, user2: userId },
      ],
    });

    console.log("Target chat: ", targetChat);

    if (!targetChat) {
      const createdChat = new ChatModel({
        user1: userId,
        user2: to,
        messages: [newMessage],
      });

      await createdChat.save();

      console.log("Created chat: ", createdChat);

      await socket.join(createdChat._id.toString());

      // find the socket of the target user
      const targetSocket = socketsByUserId.get(to);
      if (targetSocket) await targetSocket.join(createdChat._id.toString());

      socket.rooms.forEach((room) => {
        console.log(`Socket ${socket.id} is in room ${room}`);
      });
      targetSocket?.rooms.forEach((room) => {
        console.log(`Socket ${targetSocket?.id} is in room ${room}`);
      });

      io.to(createdChat._id.toString()).emit("message", messageToEmit);

      return;
    }

    targetChat.messages.push(newMessage);
    const updatedTargetChat = await targetChat.save();

    console.log("Updated chat: ", updatedTargetChat);

    io.to(updatedTargetChat._id.toString()).emit("message", messageToEmit);
  });

  socket.on("disconnect", () => {
    logger.info(`Socket disconnected: ${socket.id}`);
  });
});

export default app;
