import { model, Schema } from "mongoose";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import crypto from "crypto";

const userSchema = new Schema({
    firstName: {
        type: String,
        required: [true, "First Name is required"],
        minLength: [4, "Name must be atleast 5 character"],
        maxLength: [40, "Name should be less then 40 character"],
        trim: true
    },
    lastName: {
        type: String,
        minLength: [3, "Last Name must be atleast 5 character"],
        trim: true,
        unique: true
    },
    email: {
        type: String,
        required: [true, "Email is required"],
        trim: true,
        unique: true
    },
    password: {
        type: String,
        required : [true, "Password is required"],
        minLength: [6, "Password must be atleast 6 character"],
        select: false
    },
    avatar: {
        type: String,
    },
    role: {
        type: String,
        required: true,
        default: "user",
        enum: ["admin", "manager", "user"]
    },
    forgotPasswordToken: String,
    forgotPasswordExpiry: Date,
}, {
    timestamps: true
});

userSchema.pre('save', async function(next) {
    if (!this.isModified('password')) {
        return next();
    };
    this.password = await bcrypt.hash(this.password, Number(process.env.SALT));
})

userSchema.methods = {
    generateJWTToken: async function() {
        return await jwt.sign(
            {_id: this._id, firstName: this.firstName, email: this.email, role: this.role},
            process.env.JWT_SECRET,
            {
                expiresIn: process.env.JWT_EXPIRY
            }
        )
    },

    comparePassword: async function(plainTextPassword) {
        return await bcrypt.compare(plainTextPassword, this.password)
    },

    generatePasswordResetToken: async function() {
        const resetToken = crypto.randomBytes(20).toString("hex");

        this.forgotPasswordToken = crypto.createHash('sha256').update(resetToken).digest('hex');     // Hasing token

        this.forgotPasswordExpiry = Date.now() + 15 * 60 * 1000;         // 15 min from now expires token

        return resetToken;
    }
}

const User = model("User", userSchema);

export default User;