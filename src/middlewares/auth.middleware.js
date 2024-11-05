import jwt from 'jsonwebtoken';
import {asyncHandler} from '../utils/asyncHandler.js';
import {ApiError} from '../utils/ApiError.js';
import {User} from '../models/user.model.js';

export const verifyJwt = asyncHandler(async(req,res,next)=>{
    try {
        const token = req.cookies?.accessToken || req.headers.authorization?.replace("Bearer ","");
        if(!token){
            throw new ApiError(401, "Unauthorized");
        }
        const decodedToken =  jwt.verify(
            token,
            process.env.ACCESS_SECRECT_TOKEN
        );
        // console.log(decodedToken);
        const user = await User.findById(decodedToken?._id).select("-password -refreshToken");
        if(!user){
            throw new ApiError(401,"inavaild user token");
        }
        req.user = user;
        next();

        
    } catch (error) {
        throw new ApiError(401, "Unauthorized");
    }

})