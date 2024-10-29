import mongoose from "mongoose";
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';

const userSchema = new mongoose.Schema({
   username:{
    type: String,
    required: true,
    unique: true,
    trim: true,
    lowercase: true,
    index: true,
   },
   email:{
    type: String,
    required: true,
    unique: true,
    trim: true,
    lowercase: true,
   },
   fullNmae:{
    type: String,
    required: true,
    trim: true,
    index: true,
   },
   avatar:{
    type:String,
    required: [true, "Please provide a profile image"],
   },
   coverImage:{
    type:String,
   },
   password:{
    type: String,
    required: true,
   },
   refreshToken:{
    type: String,
   },
   watchHistory:[
    {
        type: mongoose.Schema.Types.ObjectId,
        ref: "Video",
    }
   ]
},{timestamps: true});

userSchema.pre("save", async function(next){
    if(!this.isModified("password")) return next();
    bcrypt.hash(this.password, 10);
    next();
})

userSchema.methods.isPasswordMatch = async function(password){
    return bcrypt.compare(password,this.password);
}

userSchema.methods.generateSecrectToken = function(){
    jwt.sign(
        {
            _id: this._id,
            username: this.username,
            fullName: this.fullName,
        },
        process.env.ACCESS_SECRECT_TOKEN,
        {
            expiresIn: process.env.ACCESS_SECRECT_TOKEN_EXPIRY
        }
    )
}

userSchema.methods.generateRefreshToken = function(){
    jwt.sign(
        {
            _id: this._id,
        },
        process.env.REFRESH_SECRECT_TOKEN,
        {
            expiresIn: process.env.REFRESH_SECRECT_TOKEN_EXPIRY
        }
    )
}

export const User = mongoose.model("User",userSchema);