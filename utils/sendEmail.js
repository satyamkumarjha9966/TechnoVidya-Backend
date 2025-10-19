import AppError from "./errorUtils.js"
import nodemailer from "nodemailer";

const sendEmail = async (recieverEmail, subject, message, next) => {
    try {
        const transporter = nodemailer.createTransport({
            service: "gmail",
            auth: {
                user: process.env.SENDEMAILUSER,
                pass: process.env.SENDEMAILPASSWORD
            }
        })

        const mailOption = {
            from: process.env.SENDEMAILUSER,
            to: recieverEmail,
            subject: subject,
            html: message       // html body
        }

        await transporter.sendMail(mailOption);
    } catch (error) {
        return next(new AppError(error.message, 500))
    }
}

export default sendEmail;