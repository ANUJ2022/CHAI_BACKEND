import multer from 'multer';

const storage = multer.diskStorage({
    destination: function (req, file, cb) {
        cb(null, "./public/temp")
    },
    filename: function (req, file, cb) {
        const uniqueSuffix = Date.now() + '-' + "REALME_5S"
        cb(null, file.originalname + '-' + uniqueSuffix)
        //console.log(file);
    }
    
})

export const upload = multer(
    { storage, }
)