import { Router } from "express";
import { isLoggedin, authorizedRole } from "../middlewares/authMiddleware.js";
import { allUserController, registerController, loginController, validateTokenController, logoutController, profileController, updateProfileController, deleteProfileController, changePasswordController, forgotPasswordController, resetPasswordController, changePasswordByAdminController } from "../controllers/userControllers.js";

const userRoutes = Router();

// userRoutes.route("/register").post(isLoggedin, authorizedRole('admin', 'manager'), registerController);
userRoutes.route("/register").post(registerController);
userRoutes.route("/login").post(loginController);
userRoutes.route("/validate").get(validateTokenController);
userRoutes.route("/logout").post(logoutController);
userRoutes.route("/profile/:id").get(isLoggedin, profileController).patch(isLoggedin, updateProfileController).delete(isLoggedin, deleteProfileController);
userRoutes.route("/change-password/:id").post(isLoggedin, changePasswordController);
userRoutes.route("/forgot-password").post(forgotPasswordController);
userRoutes.route("/reset-password/:resetToken").post(resetPasswordController)

// Admin Routes
// userRoutes.route("/").get(isLoggedin, authorizedRole('admin', 'manager'), allUserController)
userRoutes.route("/").get(allUserController)
// userRoutes.route("/all-staff").get(isLoggedin, authorizedRole('admin', 'manager'), allStaffUserController)
// userRoutes.route("/admin/profile/:id").get(isLoggedin,authorizedRole('admin', 'manager'), profileController).post(isLoggedin,authorizedRole('admin', 'manager'), updateProfileController);
// userRoutes.route("/admin-change-password/:id").post(isLoggedin, authorizedRole('admin'), changePasswordByAdminController);

export default userRoutes;