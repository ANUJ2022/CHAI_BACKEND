import {asyncHandler} from "../utils/asyncHandler.js";
import { ApiError } from "../utils/ApiError.js"
import {User} from "../models/user.model.js";
import {uploadOnCloudinary} from "../utils/cloudinary.js"
import { ApiResponse } from "../utils/ApiResponse.js"
import jwt from "jsonwebtoken";

const generateAccessAndRefreshTokens = async(userId) => {
    try {
        const user = await User.findById(userId);
        const refreshToken = user.generateRefreshToken();
        const accessToken = user.generateAccessToken();

        user.refreshToken = refreshToken;
        await user.save({validateBeforeSave:false});

        return {refreshToken,accessToken};

    } catch (error) {
        throw new ApiError(500,"⁕ Something went wrong while generating token ")
    }
}

const registerUser = asyncHandler(async(req,res)=>{
    //1.get user details from frontend
    //2.validation - not empty
    //3.check if user is already exist:username and email
    //4.check for images
    //5.check for avatar
    //6.upload to cloudinary, avatar
    //7.create user object - create entry in db
    //remove password and refresh token field
    //check for user creation
    //return response
    const { username, email, fullName, password } = req.body;
    console.log("Request Body:",req.body);
    if (
        [username, email, fullName, password].some(
            (field) => !field || field.trim() === ""
        )
    ) {
        throw new ApiError(400,"All fields are required");
    }
    const existedUser = await User.findOne({
        $or:[{ username },{ email }]
    })

    if(existedUser){
        throw new ApiError(409,"User with username and email is already exist");
    }
     console.log("Files",req.files);
    const avatarLocalPath = req.files?.avatar[0]?.path;
    // const coverImageLocalPath = req.files?.coverImage[0].path;
   
    let coverImageLocalPath;
    if(req.files && Array.isArray(req.files.coverImage) && req.files.coverImage.length > 0){
        coverImageLocalPath = req.files.coverImage[0].path
    }

    if(!avatarLocalPath){
        throw new ApiError(400,"Avatar is required")
    }

    const avatar = await uploadOnCloudinary(avatarLocalPath);
    const coverImage = await uploadOnCloudinary(coverImageLocalPath);
    
    if(!avatar){
         throw new ApiError(400,"Avatar is required")
    }

    const user = await User.create({
        username: username.toLowerCase(),
        email, 
        fullName,
        avatar:avatar.url,
        coverImage:coverImage?.url || "",
        password,
    });

    const createdUser = await User.findById(user._id).select(
        "-password -refreshToken"
    );
    if(!createdUser){
        throw new ApiError(500,"Something went wrong while registering user");
    }

    return res.status(201).json(
        new ApiResponse(201, createdUser, "User registered successfully")
    )

})

const loginUser = asyncHandler(async(req,res) => {
    //1.get user email or username and password from request body
    //2.validation email and password must not be empty
    //3.find user with the given email and password 
    //4.compare the password with the hash password
    //5.generate access token and refresh token 
    //6.validate if jwt token and refresh token are created or not 
    //7.return jwt token and refresh token in cookie

    const {username,email,password} = req.body;

    if(!(username || email)){
        throw new ApiError(400,"Username or email is required");
    }

    
    const user = await User.findOne({
        $or:[{username},{email}]
    })

    if(!user){
        throw new ApiError(404,"User not found")
    }

    const isPasswordValid = await user.isPasswordCorrect(password);

    if (!isPasswordValid) {
        throw new ApiError(404, "Invalid user credentials")
    }

    const{accessToken, refreshToken}= await generateAccessAndRefreshTokens(user._id);

    const loggedInUser = await User.findById(user._id).
        select("-password -refreshToken");

    const options = {
        httpOnly:true,
        secure:true
    }

    return res
    .status(200)
    .cookie("accessToken", accessToken, options)
    .cookie("refreshToken", refreshToken, options)
    .json(
        new ApiResponse(200,
        {
            user:loggedInUser,accessToken,refreshToken
        },
        "User logged in successfully"
    )
    )



})

const logoutUser = asyncHandler(async(req,res) => {
    //1.for logout we have to remove cookie and refresh token
    await User.findByIdAndUpdate(
        req.user._id,{
            $set:
            {
                refreshToken:undefined
            },
        },
        {
            new:true
        }
    )
    const options = {
        httpOnly: true,
        secure: true
    }
    return res
    .status(200)
    .clearCookie("accessToken",options)
    .clearCookie("refreshToken",options)
    .json(new ApiResponse(200,{},"User logout successfully"))
})

const refreshAccessToken = asyncHandler(async (req,res)=>{
    //1.get refresh token from cookies
    const incomingRefreshToken = req.cookies.refreshToken || req.body.refreshToken ;
    if(!incomingRefreshToken){
        throw new ApiError(401,"Unauthorized request");
    }
    
    try {
        const decodedToken = jwt.verify(incomingRefreshToken, process.env.REFRESH_TOKEN_SECRET);

        const user = await User.findById(decodedToken?._id)
        if (!user) {
            throw new ApiError(401, "Invakid refresh token")
        }
        if (incomingRefreshToken !== user?.refreshToken) {
            throw new ApiError("401", "Refresh token is expired or used");
        }
        const options = {
            httpOnly: true,
            secure: true
        }

        const { accessToken, newRefreshToken } = await generateAccessAndRefreshTokens(user._id);
        res.status(200)
            .cookie("accessToken", accessToken)
            .cookie("refreshToken", newRefreshToken)
            .json(
                new ApiResponse(200, { accessToken, newRefreshToken }, "Access token refresh successfully")
            )
    } catch (error) {
        throw new ApiError(401,error.mesage || "Invalid Token")
    }
})


export { registerUser, loginUser, logoutUser, refreshAccessToken };