import {v2 as cloudinary} from 'cloudinary';
import fs from 'fs';
import { asyncHandler } from './asyncHandler.js';


cloudinary.config({
    cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
    api_key: process.env.CLOUDINARY_API_KEY,
    api_secret: process.env.CLOUDINARY_API_SECRET
});

const uploadOnCloudinary = async (localFilePath)=> {
    try {
        if(!localFilePath){
            return null
        }
        //upload file in cloudinary
        const response = await cloudinary.uploader.upload(localFilePath,{
            resource_type:'auto'
        })
        //file has been uploaded
        // console.log("File is uploaded on cloudinary",response.url);
        console.log("Cloudinary Response:",response);
        fs.unlinkSync(localFilePath)
        return response;
    } catch (error) {
        fs.unlinkSync(localFilePath);//remove the locally saved temporary file as the upload operation got failed
        return null;
    }
}

// Function to extract public_id from URL
const getPublicIdFromUrl = (url) => {
    const regex = /\/upload\/(?:v\d+\/)?([^\.]+)/;
    const match = url.match(regex);
    return match ? match[1] : null;
};

// Function to delete an image using URL
const deleteImageByUrl = async (url) => {
    const publicId = getPublicIdFromUrl(url);
    if (!publicId) {
        console.error("Could not extract public_id from URL.");
        return;
    }

    try {
        const response = await cloudinary.uploader.destroy(publicId);
        console.log("Image deleted successfully:", response);
    } catch (error) {
        console.error("Error deleting image:", error);
    }
};

const replaceImage = async (localFilePath, publicId) => {
    try {
        const response = await cloudinary.uploader.upload(localFilePath, {
            public_id: publicId, // Reuse the same public_id
            overwrite: true, // Ensure replacement
        });
        console.log("Image replaced successfully:", response);
    } catch (error) {
        console.error("Error replacing image:", error);
    }
};


export {uploadOnCloudinary}