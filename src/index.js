import dotenv from 'dotenv'
import connectDB from './db/index.js';
import { app } from './app.js';
dotenv.config({path:'./.env'});



connectDB()
.then(()=>{
  app.listen(process.env.PORT || 8000 , ()=>{
    console.log(`Server is running on port ${process.env.PORT}`);
  })
})
.catch((err)=>{
  console.log("mongoDB connection failed \n",err);
})














//first approach to connect to the database
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