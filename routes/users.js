const express = require('express');
// to use express router-->
const router = express.Router();
const bcrypt = require('bcryptjs');
const passport = require('passport');

// user model
const User = require('../models/User');
const { forwardAuthenticated } = require('../config/auth');

// Login Page
router.get('/login', forwardAuthenticated, (req, res) => res.render('login'));

// Register Page
router.get('/register', forwardAuthenticated, (req, res) => res.render('register'));

// login page
router.get('/login',(req,res)=>res.render('login'));

// register page
router.get('/register',(req,res)=>res.render('register'));

//handle register
router.post('/register',(req,res)=>{
    // destructuring to get the data within body
    const{name,email,password,password2}=req.body;
    let errors = [];

    // check required fields
    if(!name||!email||!password||!password2){
        errors.push({msg:'Please fill in all fields'});
    }

    // check passwords match
    if(password!=password2){
        errors.push({msg:'Passwords do not match'});
    }

    // check pass length
    if(password.length<6){
        errors.push({msg:'Password should be at least 6 characters'})
    }

    if(errors.length>0){
        res.render('register',{
            // we also pass the data because we dont want 
            // the data in fields to vanish if any error occurs
            // we will use partials to display the errors 
            errors,
            name,
            email,
            password,
            password2
        });
    }else{
        // validation passed
        User.findOne({email:email})
        .then(user=>{
            if(user){
                // user exists
                errors.push({msg:'Email is already registered'});
                res.render('register',{
                    errors,
                    name,
                    email,
                    password,
                    password2
                });
            }else{
                const newUser = new User({
                    name, //this is same as name:name(es6)
                    email,
                    password
                });
                
                // hash password
                bcrypt.genSalt(10,(err,salt)=>bcrypt.hash(newUser.password,salt,(err,hash)=>{
                    if(err) throw err;
                // set password to hash
                    newUser.password=hash;
                // save user to database
                newUser.save()
                .then(user=>{
                    req.flash('success_msg','You are now registered and can login');
                    res.redirect('/users/login');
                })
                .catch(err=>console.log(err));
                }))
            }
        })
    }
});

// Login
router.post('/login', (req, res, next) => {
    passport.authenticate('local', {
      successRedirect: '/dashboard',
      failureRedirect: '/users/login',
      failureFlash: true
    })(req, res, next);
  });

// Logout
router.get('/logout', (req, res) => {
    req.logout();
    req.flash('success_msg', 'You are logged out');
    res.redirect('/users/login');
  });
module.exports= router;