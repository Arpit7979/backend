import mongoose from "mongoose";
import { DB_NAME } from "../constants.js";

const connectDB = async ()=>{
    try {
      const connectionInstance= await mongoose.connect(`${process.env.MONGODB_URI}/${DB_NAME}`);
      console.log("mongoDB connected !! host: ",connectionInstance.connection.host);
    } catch (error) {
        console.error("mongoDB connection failed \n",error);
        process.exit(1);
    }
}

export default connectDB;