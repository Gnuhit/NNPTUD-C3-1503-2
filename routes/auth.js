var express = require("express");
var router = express.Router();
let userController = require('../controllers/users')
let { body } = require('express-validator')
let { RegisterValidator, validatedResult } = require('../utils/validator')
let {CheckLogin} = require('../utils/authHandler')
//login
router.post('/login',async function (req, res, next) {
    let { username, password } = req.body;
    let result = await userController.QueryLogin(username,password);
    if(!result){
        res.status(404).send("thong tin dang nhap khong dung")
    }else{
        res.send(result)
    }
    
})
router.post('/register', RegisterValidator, validatedResult, async function (req, res, next) {
    let { username, password, email } = req.body;
    let newUser = await userController.CreateAnUser(
        username, password, email, '69b6231b3de61addb401ea26'
    )
    res.send(newUser)
})
router.get('/me',CheckLogin,function(req,res,next){
    res.send(req.user)
})

router.post('/changepassword',
    CheckLogin,
    body('oldPassword').notEmpty().withMessage('oldPassword khong duoc de trong'),
    body('newPassword').notEmpty().withMessage('newPassword khong duoc de trong').bail().isStrongPassword({
        minLength: 8,
        minLowercase: 1,
        minUppercase: 1,
        minNumbers: 1,
        minSymbols: 1
    }).withMessage('newPassword phai tu 8 ky tu, co hoa, thuong, so, ky tu dac biet'),
    validatedResult,
    async function (req, res, next) {
        try {
            let { oldPassword, newPassword } = req.body;
            let result = await userController.ChangePassword(req.user._id, oldPassword, newPassword);
            res.send(result);
        } catch (err) {
            if (err.message === 'old_password_incorrect') {
                res.status(400).send({ message: 'oldPassword khong chinh xac' });
            } else if (err.message === 'user_not_found') {
                res.status(404).send({ message: 'user khong ton tai' });
            } else {
                res.status(500).send({ message: 'doi mat khau that bai' });
            }
        }
    }
)

//register
//changepassword
//me
//forgotpassword
//permission
module.exports = router;