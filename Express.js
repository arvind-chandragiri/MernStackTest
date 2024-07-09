// Implement an Express.js route that allows an authenticated user (identified by userId from JWT) to update their password securely using bcrypt for hashing.
// import Express from 'express';
const express = require('express');
const bcrypt = require('bcrypt');
const JWT = require('JSONWebtoken')

const router = express.Router();
const secret_key = 'Mysecretkey';

const verifyToken = async(req,res,next)=>{
    const token = req.headers['Authorization'];
    if(!token){
        return res.status().json({message:'Unauthorized access'});
    }
    try{
        const decoded = jwt.verify(token, secretKey);
    req.userId = decoded.userId;
    next();
    } 
    catch (err) {
    res.status(401).json({ message: 'Invalid token' });
    };

    router.put('/update-password', verifyToken, async (req, res) => {
        const { userId } = req;
        const { currentPassword, newPassword } = req.body;
      
    }
    if (!currentPassword || !newPassword) {
        return res.status(400).json({ message: 'Missing required fields' });
    }
    const user = await getUserData(userId);
    if (!user) {
    return res.status(404).json({ message: 'User not found' });
    const isPasswordMatch = await bcrypt.compare(currentPassword, user.password);
    if (!isPasswordMatch) {
        return res.status(401).json({ message: 'Incorrect current password' });
    }

    const saltRounds = 10;
    const hashedPassword = await bcrypt.hash(newPassword, saltRounds);
   
    await updateUserData(user, { password: hashedPassword });
  
    res.json({ message: 'Password updated successfully' });
  });
  
  async function getUserData(userId) {
  }
  
  async function updateUserData(userId, updateData) {
  }
}
  module.exports = router;

// const app = Express();
// const URL = "localhost"