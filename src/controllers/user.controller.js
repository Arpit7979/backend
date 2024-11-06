import {asyncHandler} from '../utils/asyncHandler.js';
import {ApiError} from '../utils/ApiError.js';
import {User} from  "../models/user.model.js";
import {uploadOnCloudinary} from "../utils/cloudinary.js";
import {ApiResponse} from "../utils/Apiresponse.js";
import jwt from 'jsonwebtoken';


const generateAccessAndRefreshToken = async(userId)=>{
    try {
        const user = await User.findById(userId);
        const accessToken = user.generateSecrectToken();
        const refreshToken = user.generateRefreshToken();
        // console.log("access token",accessToken, "refresh token",refreshToken);
        user.refreshToken = refreshToken;
        await user.save({validateBeforeSave: false});

        return {accessToken, refreshToken};
    } catch (error) {
        throw new ApiError(500, "Failed to generate access and refresh token");
    }
}

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

    const {username,email,fullName,password} = req.body;
    console.log(email);

    if([username,email,password,fullName].some((field)=>field?.trim() === '')){
        throw new ApiError(400,"Please fill all the fields");
    }

    const existedUser = await User.findOne({
        $or: [{username},{email}]
    });

    if(existedUser){
        throw new ApiError(409, "User already exist with this email or username");
    }

    // console.log("files ", req.files );
    const avatarLocalPath = req.files?.avatar[0]?.path;
    // const coverImageLocalPath = req.files?.coverImage[0]?.path;

    let coverImageLocalPath;
    if(req.files && Array.isArray(req.files.coverImage) && req.files.coverImage.length > 0){
        coverImageLocalPath = req.files.coverImage[0].path;
    }

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
        fullName,
        avatar: avatar.url,
        coverImage: coverImage?.url || '',
    });

    const createdUser = await User.findById(user._id).select("-password -refreshToken");

    if(!createdUser){
        throw new ApiError(500, "Failed to create user");
    }

    return res.status(201).json(
        new ApiResponse(200, createdUser, "User created successfully")
    )
});

const loginUser = asyncHandler(async (req,res)=>{
    //steps to login a user 
    //get user data
    //login based on email or username
    //check user exist or not
    //check password is correct or not
    //generate refresh token and access token
    //send cookie

    const {email,username,password}  = req.body;

    if(!(email || username)){
        throw new ApiError(400, "Please provide email or username");
    }

    const user = await User.findOne({
        $or: [{email},{username}]
    });

    if(!user){
        throw new ApiError(404, "User not found");
    };

    // all methods applied on the user response that we get above not on the User model
    const isPasswordValid =  await user.isPasswordMatch(password);

    if(!isPasswordValid){
        throw new ApiError(401, "Invalid credentials");
    }

    const {accessToken,refreshToken} = await generateAccessAndRefreshToken(user._id);

    // above user have empity refresh token so we need to query again to get the set refresh token
    const loggedInUser = await User.findById(user._id).select("-password -refreshToken");

    const options = {
        httpOnly: true,
        secure: true,
    }

    return res
    .status(200)
    .cookie("refreshToken",refreshToken , options)
    .cookie("accessToken",accessToken , options)
    .json(
        new ApiResponse(
        200,  
        {
            user:loggedInUser,
            refreshToken,
            accessToken
        }
        ,"User logged in successfully"

     )
    )
});

const logoutUser = asyncHandler(async (req, res)=>{
   User.findByIdAndUpdate(
         req.user._id,
         {
            $set:{refreshToken: undefined}
         },
         {
            new: true,
         }
   );

   const options = {
      httpOnly: true,
      secure: true,
   }

   return res
   .status(200)
   .clearCookie("refreshToken",options)
   .clearCookie("accessToken",options)
   .json(
      new ApiResponse(
          200,
          {},
        "User logged out successfully",
      )
   )
})

//actually access token is short lived token and refresh token is long lived token so we need to refresh access token after some time and we can do this by using refresh token that we save in cookie and mongoDB database so we need to check if the refresh token is valid or not and if it is valid then we need to generate new access token and refresh token and send it to the user
const refreshAccessToken = asyncHandler(async(req,res)=>{
  const incomingRefreshToken = req.cookies?.refreshToken || req.body?.refreshToken;

  if(!incomingRefreshToken){
     throw new ApiError(401, "Unauthorized access");
  }

  try {
    const decodedRefreshToken = jwt.verify(incomingRefreshToken, process.env.REFRESH_SECRECT_TOKEN);
  
    if(!decodedRefreshToken){
       throw new ApiError(401, "Unable to decode refresh token");
    }
  
    const user = await User.findById(decodedRefreshToken._id);
  
    if(!user){
          throw new ApiError(401, "User not found with this refresh token");
     }
  
     if(user.refreshToken !== incomingRefreshToken){
          throw new ApiError(401, "Invalid refresh token");
     }
  
     const {accessToken,refreshToken} = await generateAccessAndRefreshToken(user._id);
  
     const options = {
       httpOnly: true,
       secure: true,
     }
  
     return res
     .status(200)
     .cookie("refreshToken",refreshToken,options)
     .cookie("accessToken",accessToken,options)
     .json(
       new ApiResponse(
          200,
          {
              accessToken,
              refreshToken
          },
          "Access token refreshed successfully"
       )
     )
  } catch (error) {
      throw new ApiError(401, error?.message || "Invalid refresh token");
    
  }

});

const changeCurrentPassword = asyncHandler(async(req,res)=>{
    const {oldPassword,newPassword} = req.body;
    const user = await User.findById(req.user?._id);
    if(!user){
        throw new ApiError(404, "User not found");
    }
    const isOldPasswordCorrect = await user.isPasswordMatch(oldPassword);
    if(!isOldPasswordCorrect){
        throw new ApiError(400, "Invalid old password");
    }
    user.password = newPassword;
    await user.save({validateBeforeSave: false});

    return res
    .status(200)
    .json(
        new ApiResponse(200,{}, "Password changed successfully")
    )
});

const getCurrentUser = asyncHandler(async(req,res)=>{
    return res
    .status(200)
    .json(
        new ApiResponse(200, req.user, "User found successfully")
    )
})

const updateAccountDetails = asyncHandler(async(req,res)=>{
    const {fullName,email} = req.body;

    if(!fullName || !email){
        throw new ApiError(400, "Please provide full name and email");
    };

    const user = await User.findByIdAndUpdate(
        req.user._id,
        {
            $set:{
                fullName,
                email,
            }
        },
        {
            new: true, // return updated document
        }
    ).select("-password");

    return res
    .status(200)
    .json(new ApiResponse(200, user, "User updated successfully"))
});

const updateUserAvatar = asyncHandler(async(req,res)=>{
    // const avatarLocalPath = req.file?.avatar[0]?.path;
		const avatarLocalPath = req.file?.path;
    if(!avatarLocalPath){
        throw new ApiError(400, "avatar file is missing");
    };
    const avatar = await uploadOnCloudinary(avatarLocalPath);

    if(!avatar.url){
        throw new ApiError(400, "Failed to upload avatar on cloudinary");
    }

    const user = await User.findByIdAndUpdate(
        req.user._id,
        {
            $set:{
                avatar: avatar.url,
            }
        },
        {
            new: true,
        }
    ).select("-password");

    return res
    .status(200)
    .json(new ApiResponse(200, user, "Avatar updated successfully"));
});

const updateCoverImage = asyncHandler(async(req,res)=>{
    // const coverImageLocalPath = req.file?.coverImage[0]?.path;
		const coverImageLocalPath = req.file?.path;
    if(!coverImageLocalPath){
        throw new ApiError(400, "coverImage file is missing");
    };
    const coverImage = await uploadOnCloudinary(coverImageLocalPath);

    if(!coverImage.url){
        throw new ApiError(400, "Failed to upload coverImage on cloudinary");
    }

    const user = await User.findByIdAndUpdate(
        req.user._id,
        {
            $set:{
                coverImage: coverImage.url,
            }
        },
        {
            new: true,
        }
    ).select("-password");

    return res
    .status(200)
    .json(new ApiResponse(200, user, "coverImage updated successfully"));
})

const getUserChannelProfile = asyncHandler(async(req,res)=>{
	const {username} = req?.param;
	
	if(!username){
		throw new ApiError(400, "Username not found");
	}
	
	//aggregation pipeline
	const channel = await User.aggregate([
		{
			$match:{
				username: username?.toLowerCase(),
			}
		},
		{
			$lookup:{
				from:"subscriptions",
				localField:"_id",
				foreignField:"channel",
				as:"subscribers",
			}
		},
		{
			$lookup:{
				from:"subscriptions",
				localField:"_id",
				foreignField:"subscriber",
				as:"subscribedTo",
			}
		},
		{
			$addFields:{
				subscribersCount:{
					$size:"$subscribers"
				},
				subscribedToCount:{
					$size:"$subscribedTo"
				},
				isSubscribed:{
					$cond:{
						if:{$in:[req.user?._id,"$subscribers.subscriber"]},
						then:true,
						else:false,
					}
				}
			}
		},
		{
			$project:{
				username:1,
				fullName:1,
				avatar:1,
				email:1,
				subscribersCount:1,
				subscribedToCount:1,
				isSubscribed:1,
			  coverImage:1,
			}
		}
	]);

	if(!channel.length){
		throw new ApiError(404, "Channel does not exist");
	};

	return res
	.status(200)
	.json(
		new ApiResponse(200, channel[0], "User Channel fetched successfully")
	)
})

export {
      registerUser,
      loginUser,
      logoutUser,
      refreshAccessToken,
      changeCurrentPassword,
      getCurrentUser,
      updateAccountDetails,
      updateUserAvatar,
      updateCoverImage,
			getUserChannelProfile,
    };