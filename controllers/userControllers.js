import User from "../models/userModel.js";
import AppError from "../utils/errorUtils.js";
import sendEmail from "../utils/sendEmail.js";
import crypto from "crypto";
import jwt from "jsonwebtoken";

const cookieOptions = {
    maxAge: 7*24*60*60*1000,     // 7 Days
    httpOnly: true,    // For secure
    secure: true
}

const allUserController = async (req, res, next) => {
    try {
        const users = await User.find({}).sort({_id: -1});         //sort("-_id")  both work

        return res.status(200).json({
            success: true,
            message: "Users fetched successfully",
            data: users
        });
    } catch (error) {
        return next(new AppError(error.message, 500));
    }
};

const registerController = async (req, res, next) => {
    try {
        const { firstName, lastName, email, password, avatar } = req.body;

        if (!firstName || !email || !password) {
            return next(new AppError("All fields are required for registration", 400));
        }

        const isEmailExist = await User.findOne({email});

        if (isEmailExist) {
            return next(new AppError("Email already exist. Please try with another email", 400));
        }

        const user = await User.create({
            firstName,
            lastName,
            email,
            password,
            avatar: avatar || null,
        });

        if (!user) {
            return next(new AppError("User registration failed, Please try again", 500))
        }

        user.password = undefined

        // const token = await user.generateJWTToken();

        // res.cookie('token', token, cookieOptions);

        res.status(200).send({
            success: true,
            message: "User Register SuccessfullY",
            user
        })
    } catch (error) {
        return next(new AppError(error.message, 500))
    }
};

const loginController = async (req, res, next) => {
    try {
        const { email, password } = req.body;

        if (!email || !password) {
            return next(new AppError("All fields are required", 400));
        }

        const user = await User.findOne({
            email
        }).select('+password');

        if (!user) {
            return next(new AppError("User not found with this email! Please register first", 400))
        }

        const isPasswordMatch = await user.comparePassword(password);

        if (!user || !isPasswordMatch) {
            return next(new AppError("Password does not match", 400));
        }

        const token = await user.generateJWTToken();

        user.password = undefined;

        res.cookie('token', token, cookieOptions);

        res.status(200).send({
            success: true,
            message: "User Logged in successfully",
            user: user,
            token: token
        });
    }
    catch (error) {
        return next(new AppError(error.message, 500));
    }
};

const validateTokenController = async (req, res, next) => {
    try {
        const token = req.cookies.token;

        if (!token) {
            return next(new AppError("Token not found", 400))
        }

        const decodedToken = jwt.verify(token, process.env.JWT_SECRET);

        res.status(200).send({
            success: true,
            message: "Token verified",
            user: decodedToken
        })
    } catch (error) {
        return next(new AppError(error.message, 500))
    }
}

const logoutController = async (req, res, next) => {
    try {
        res.cookie('token', null, {
            secure: true,
            maxAge: 0,
            httpOnly: true
        });
    
        res.status(200).send({
            success: true,
            message: "Logout Successfully",
        })
    } catch (error) {
        return next(new AppError(error.message, 400))
    }
};

const profileController = async (req, res, next) => {
    try {
        const { id } = req.params;

        const user = await User.findById(id);

        if (!user) {
            return next(new AppError("User not found with given Id", 400));
        }

        return res.status(200).json({
            success: true,
            message: "User fetched successfully",
            data: user
        });
    } catch (error) {
        return next(new AppError(error.message, 500));
    }
};

const updateProfileController = async (req, res, next) => {
    try {
        const { firstName, lastName, avatar } = req.body;
        const { id } = req.params;

        const isUserExist = await User.findById(id);

        if (!isUserExist) {
            return next(new AppError("User is not avialble with this id", 400));
        }

        if (!firstName || !lastName) {
            return next(new AppError("Name and Phone Number is required", 400))
        }

        const user = await User.findByIdAndUpdate(id, {firstName: firstName, lastName: lastName, avatar: avatar}, {runValidators: true, new: true});

        if (!user) {
            return next(new AppError("Profile not updated. Please try again"))
        }

        res.status(200).send({
            success: true,
            message: "User details updated successfully",
        })
    } catch (error) {
        return next(new AppError(error.message, 500))
    }
};

const deleteProfileController = async (req, res, next) => {
    try {
        const { id } = req.params;

        const user = await User.findById(id);

        if (!user) {
            return next(new AppError("User with this id does not exist", 400));
        }

        await User.findByIdAndDelete(id);

        res.status(200).send({
            success: true,
            message: "User deleted Successfully"
        })
    } catch (error) {
        return next(new AppError(error.message, 500));
    }
};

const changePasswordController = async (req, res, next) => {
    try {
        const { id } = req.params;
        const { oldPassword, newPassword, confirmNewPassword } = req.body;

        if (!oldPassword || !newPassword || !confirmNewPassword) {
            return next(new AppError("Old and New password both are required", 400));
        }

        if (newPassword !== confirmNewPassword) {
            return next(new AppError("New password does not match with confirm password", 400))
        }

        const user = await User.findById(id).select("+password");

        if (!user) {
            return next(new AppError("User is not present with this id", 400));
        }

        const compareOldPassword = await user.comparePassword(oldPassword);

        if (!compareOldPassword) {
            return next(new AppError("Old password does not match", 400))
        }

        user.password = newPassword;

        await user.save();

        user.password = undefined;

        res.status(200).send({
            success: true,
            message: "Password change successfully",
        })
    } catch (error) {
        return next(new AppError(error.message, 500))
    }
}

const forgotPasswordController = async (req, res, next) => {
    try {
        const { email } = req.body;

        if (!email) {
            return next(new AppError("Email is required for reset password!", 400))
        }

        const user = await User.findOne({email: email});

        if (!user) {
            return next(new AppError("User is not found With this Email", 400))
        }

        const resetToken = await user.generatePasswordResetToken();

        await user.save();

        const resetPasswordURL = `${process.env.FRONTEND_URL}/reset-password/${resetToken}`;

        const subject = "Reset Password";
        const message = `You can reset your password by clicking <a href=${resetPasswordURL} target="_blank">Reset your password</a>\n If the above link does not work for some reason then copy paste this link in new tab ${resetPasswordURL}.\n If you have not requested this, kindely ignored!`;

        try {
            await sendEmail(email, subject, message);

            res.status(200).json({
                success: true,
                message: `Reset password token has been sent to ${email} successfully`,
            })
        } catch (error) {
            user.forgotPasswordToken = undefined;
            user.forgotPasswordExpiry = undefined;

            await user.save();

            return next(new AppError(error.message, 400))
        }
    } catch (error) {
        return next(new AppError(error.message, 500))
    }
}

const resetPasswordController = async (req, res, next) => {
    try {
        const { resetToken } = req.params;
        const { password, confirmPassword } = req.body;

        if (!password || !confirmPassword) {
            return next(new AppError("Password and confirm password are require", 400))
        }

        if (password !== confirmPassword) {
            return next(new AppError("New password does not match with confirm password", 400))
        }

        const hashedForgotPasswordToken = crypto.createHash('sha256').update(resetToken).digest('hex');

        const user = await User.findOne({
            forgotPasswordToken: hashedForgotPasswordToken,
            forgotPasswordExpiry: {$gt: Date.now()}
        });

        if (!user) {
            return next(new AppError("Token is invalid or expired, Please try again", 400))
        }

        user.password = password;
        user.forgotPasswordToken = undefined;
        user.forgotPasswordExpiry = undefined;

        user.save();

        res.status(200).send({
            success: true,
            message: "Password changed successfully"
        })
    } catch (error) {
        return next(new AppError(error.message, 500))
    }
}

const changePasswordByAdminController = async (req, res, next) => {
    try {
        const { newPassword, confirmNewPassword } = req.body;
        const { id } = req.params;

        if (!newPassword || !confirmNewPassword) {
            return next(new AppError("Password and confirm password both are require", 400))
        }

        if (newPassword !== confirmNewPassword) {
            return next(new AppError("New password does not match with confirm password", 400))
        }

        const user = await User.findById(id);

        if (!user) {
            return next(new AppError("User not find with this id", 400));
        }

        user.password = newPassword;

        await user.save();

        user.password = undefined;

        res.status(200).send({
            success: true,
            message: "User password chnages successfully",
        })
    } catch (error) {
        return next(new AppError(error.message, 500))
    }
}

export { allUserController, registerController, loginController, validateTokenController, logoutController, profileController, updateProfileController, deleteProfileController, changePasswordController, forgotPasswordController, resetPasswordController, changePasswordByAdminController };