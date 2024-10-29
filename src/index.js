//first approach to connect to the database
import dotenv from 'dotenv'
import connectDB from './db/index.js';
dotenv.config({path:'./.env'});



connectDB();














// const app = express();

// (async()=>{
//     try {
//       await mongoose.connect(`${process.env.MONGODB_URI}/${process.env.DB_NAME}`);
//       app.on("error",(error)=>{
//         console.log("error :", error);
//         throw error;
//       });

//       app.listen(process.env.PORT,()=>{
//         console.log(`Server is running on port ${process.env.PORT}`);
//       });
//     } catch (error) {
//         console.error(error);
//         throw error;
//     }
// })()