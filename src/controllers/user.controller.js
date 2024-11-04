import {asyncHandler} from '../utils/asyncHandler.js';
import {ApiError} from '../utils/ApiError.js';
import {User} from  "../models/user.model.js";
import {uploadOnCloudinary} from "../utils/cloudinary.js";


const registerUser = asyncHandler(async (req,res)=>{
    
    //steps to register a user
    // get user data from frontend
    // validate
    // check user is already exist or not
    // check for avatar
    // upload on cloudinary
    // create user object and save in database
    // remove password and refresh token from response
    // check for user created or not
    // send response

    const {usernmae,email,fullNmae,password} = req.body;
    console.log(email);

    if([usernmae,email,password,fullNmae].some((field)=>field?.trim() === '')){
        throw new ApiError(400,"Please fill all the fields");
    }

    const existedUser = User.findOne({
        $or:[{username},{email}]
    });

    if(existedUser){
        throw new ApiError(409, "User already exist with this email or username");
    }

    const avatarLocalPath = req.files?.avatar[0]?.path;
    const coverImageLocalPath = req.files?.coverImage[0]?.path;

    if(!avatarLocalPath){
        throw new ApiError(400, "Please provide a profile image");
    };

    const avatar = await uploadOnCloudinary(avatarLocalPath);
    const coverImage = await uploadOnCloudinary(coverImageLocalPath);

    if(!avatar){
        throw new ApiError(500, "Failed to upload avatar on cloudinary");
    }

    const user = await User.create({
        username,
        email,
        password,
        fullNmae,
        avatar: avatar.url,
        coverImage: coverImage?.url || '',
    });

    const createdUser = await User.findById(user._id).select("-password -refreshToken");

    if(!createdUser){
        throw new ApiError(500, "Failed to create user");
    }
});

export {registerUser};