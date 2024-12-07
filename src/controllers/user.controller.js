import {asyncHandler} from "../utils/asyncHandler.js";
import { ApiError } from "../utils/ApiError.js"
import {User} from "../models/user.model.js";
import {uploadOnCloudinary} from "../utils/cloudinary.js"
import { ApiResponse } from "../utils/ApiResponse.js"
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



export {registerUser};