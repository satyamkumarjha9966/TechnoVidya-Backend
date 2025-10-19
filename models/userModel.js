import { model, Schema } from "mongoose";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import crypto from "crypto";

const userSchema = new Schema({
    name: {
        type: String,
        required: [true, "Name is required"],
        minLength: [4, "Name must be atleast 5 character"],
        maxLength: [40, "Name should be less then 40 character"],
        trim: true
    },
    username: {
        type: String,
        required: [true, "Username is required"],
        minLength: [5, "Username must be atleast 5 character"],
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
    phoneNumber: {
        type: Number,
        required: [true, "Phone Number is required"],
        minLength:[10,"Phone Number must be of 10 numbers"],
        trim: true
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
            {_id: this._id, username: this.username, name: this.name, email: this.email, role: this.role},
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