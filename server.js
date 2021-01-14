import express from "express";
import cors from "cors";
import mongoose from "mongoose";
import expressSession from "express-session";
import MongoStore from "connect-mongodb-session";
import dotenv from "dotenv";
import AuthRoute from "./src/Routes/Auth/Auth";
dotenv.config();

const app = express();

//===================================++++Middleware++++=======================================================
app.use(
  cors({
    origin: "http://localhost:3000",
    credentials: true,
  })
);
const mongoURI = process.env.mongoURI;
mongoose.connect(
  mongoURI,
  { useUnifiedTopology: true, useNewUrlParser: true },
  (error) => {
    if (error) {
      return console.error(error);
    }
    return console.log("Connection to MongoDB was successfully.");
  }
);

app.use(AuthRoute);
//======================================================================================================================
const PORT = process.env.PORT || 5000;

app.listen(PORT, () => {
  console.log(`Server started  on PORT ${PORT}`);
});
