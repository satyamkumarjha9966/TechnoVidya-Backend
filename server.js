import app from "./app.js";
import connectDB from "./config/dbConnection.js";

const PORT = process.env.PORT;

app.listen(PORT, async () => {
    console.log(`Server is running on port ${PORT}`);
    await connectDB();
})