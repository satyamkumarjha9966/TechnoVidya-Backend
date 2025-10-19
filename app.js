import express from "express";
import dotenv from "dotenv";
import cors from "cors";
import cookieParser from "cookie-parser";
import morgan from "morgan";
import errorMiddleware from "./middlewares/errorMiddleware.js";
import userRoutes from "./routes/userRoutes.js";
dotenv.config();

const app = express();

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cors({
    origin: [process.env.FRONTEND_URL],
    credentials: true
}));
app.use(cookieParser());
app.use(morgan("dev"));

app.get("/test", (req, res) => {
    res.send("Server is running")
});

// All Routes
app.use("/api/v1/users", userRoutes)

// 404 handler - keep it after all routes
app.use((req, res) => {
    res.status(400).send("OOPS!, Page not found.");
})

app.use(errorMiddleware)

export default app;