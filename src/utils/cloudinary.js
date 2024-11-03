import {v2 as cloudinary} from 'cloudinary';
import fs from 'fs'

cloudinary.config({ 
    cloud_name: process.env.CLOUDINARY_CLOUD_NAME, 
    api_key: process.env.CLOUDINARY_API_KEY, 
    api_secret: process.env.CLOUDINARY_API_SECRET,
});

const uploadOnCloudinary = async(localFilePath)=>{
    
    try {
        if(!localFilePath) return null;
        const response = await cloudinary.uploader.upload(localFilePath,{
            resource_type:'auto'
          })
      
          console.log("file uploaded successfully and its local url is ",response.url);
          return response;

    } catch (error) {
        fs.unlinkSync(localFilePath);  // this will remove all the local saved temporary file which are not uploaded due to some issue  
    }
}

export {uploadOnCloudinary};