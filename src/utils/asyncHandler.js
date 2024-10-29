// using promise to handle async functions
const asyncHandler = (requestHandler)=>{
    return (req,res,next)=>{
        Promise.resolve(requestHandler(req,res,next)).catch((err)=>next(err));
    }
};

export {asyncHandler};

// using try and catch block to handle async functions
// const asyncHandler = (fn) => async(req,res,next) => {
//    try {
//     await fn(req,res,next);
//    } catch (error) {
//      res.status(err.code || 500).json({
//         success:false,
//         message:error.message,
//      });
//    }
// }