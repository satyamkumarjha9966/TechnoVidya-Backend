import AppError from "../utils/errorUtils.js";
import jwt from "jsonwebtoken";

const isLoggedin = async (req, res, next) => {
    const { token } = req.cookies;

    if (!token) {
        return next(new AppError('Unauthenticated, please login again', 400))
    }

    const userDetails = await jwt.verify(token, process.env.JWT_SECRET);

    req.user = userDetails;

    next();
};

const authorizedRole = (...roles) => (req, res, next) => {
    const currentUserRole = req.user.role;

    if (!roles.includes(currentUserRole)) {
        return next(new AppError("You do not have permission to access this route", 403))
    }

    next();
}

export {isLoggedin, authorizedRole};