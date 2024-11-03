import express from 'express';
import cors from 'cors';
import cookieParser from 'cookie-parser';

const app = express();

app.use(cors({
    origin:process.env.CORS_ORIGIN,
    credentials:true,
}));
app.use(express.json({limit:'16kb'}));
app.use(express.urlencoded({extended:true,limit:'16kb'}));
app.use(cookieParser());
app.use(express.static('public'));

//import router
import userRouter from '../src/route/user.route.js';

//route declear
app.use("/api/v1/user",userRouter);

export {app};