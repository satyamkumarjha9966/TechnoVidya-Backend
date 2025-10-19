import mongoose from "mongoose";

const connectDB = async () => {
    try {
        const { connection } = await mongoose.connect(process.env.MONGO_URI, {dbName: "TechnoVidyaDB"});
        if (connection) {
            console.log("Connect to MongoDB", connection.host)
        }
    } catch (error) {
        console.log(error);
        process.exit(1);
    }
}

export default connectDB;