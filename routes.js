'use strict';

const express = require('express');
const bcryptjs = require('bcryptjs');
const { check, validationResult } = require('express-validator');
const auth = require('basic-auth');
const router = express.Router();
const Users = require('./models').Users;
const Courses = require('./models').Courses;


//Handler function for try and catch 
function asyncHandler(cb){
    return async(req, res, next) =>{
        try{
            await cb(req, res, next)
        }catch(error){
            res.status(500).send(error);
        }
        
    }
}


//this array is used to keep track of user + course records
const users = [];
const courses = [];

//authentication middleware
const authenticationUser = async(req, res, next) => {
    let message = null;
    const users = await Users.findAll();
    //Parse the user's credentials fro the Authorization header.
    const credentials = auth(req);

    //if the user's credentials are available...
    if(credentials){
        const user = users.find( u => u.emailAddress === credentials.name);

        //if a user was successfully retrieved from the data store...
        if(user) {
            //use bcryptjs to compare the user's password
            const authenticated = bcryptjs
                .compareSync(credentials.pass, user.password);

            //if the password matches...
            if(authenticated) {
                console.log(`Authentication successful for username: ${user.emailAddress}`);
                req.currentUser = user;
            }else{
                message = `Authentication failure for username: ${user.emailAddress}`;
            }
        } else{
            message = `User not found for username: ${credentials.name}`;
        }
      }  else{
            message = 'Auth header not found';
        }
        //if user authentication failed...
        if(message){
            console.warn(message);
        
        //return a response with a 401 Unauthorized HTTP status
        res.status(401).json( {message: 'Access Denied'});
        }else{
            next();
        }
   
};



//Route to get users
router.get('/users', authenticationUser, asyncHandler( async(req,res) => {
    const user = req.currentUser;
    const users = await Users.findByPk(user.id, {
        attributes:{
            exclude:[
                'password',
                'createdAt',
                'updatedAt'
            ],
        }
    });
    res.status(200).json(users);
}));

//Route to create a new user
router.post('/users',  [
    check('firstName')
        .exists({ checkNull: true, checkFalsy: true })
        .withMessage('Please provide a value for "firstName"'),
    check('lastName')
        .exists({ checkNull: true, checkFalsy: true })
        .withMessage('Please provide a value for "lastName"'),
    
    check('emailAddress')
        .exists( {checkNull: true, checkFalsy: true })
        .withMessage('Please provide a value for "emailAddress"')
        .isEmail()
        .withMessage('Please provide a valid email address'),
    
    check('password')
        .exists({ checkNull: true, checkFalsy: true })
        .withMessage('Please provide a value for "password"'),
], asyncHandler(async(req, res) => {
    //Attempt to get the validation result from the Request object
    const errors = validationResult(req);

    //if there are validation errors
    if(!errors.isEmpty()) {
        const errorMessages = errors.array().map(error => error.msg);
        //return the validation errors to the client
        return res.status(400).json( { errors: errorMessages });
    }else{
        const user = req.body;

        //hash the new user's password
        user.password = bcryptjs.hashSync(user.password);
        await Users.create(req.body);

        //set status to 201 Created and end response
        return res.status(201).location('/').end();
    }
}));

//GET /api/courses 200 - Returns a list of courses 
//(including the user that owns each course)
router.get('/courses',  asyncHandler(async(req, res)=>{
    const courses = await Courses.findAll();
    res.status(200).json(courses);
}));

//GET /api/courses/:id 200 - 
//Returns a the course (including the user that owns the course) 
//for the provided course ID
router.get('/courses/:id', asyncHandler(async(req, res) =>{
    const courses = await Courses.findByPk(req.params.id);
    
    if(courses){
        res.status(200).json(courses).end();
    }else{
        res.status(400).json({message: 'Sorry course is not available'})
    }
        
    
}));


//POST /api/courses 201 - Creates a course, 
// sets the Location header to the URI for the course, 
// and returns no content
router.post('/courses', [
    check('title')
        .exists( { checkNull: true, checkFalsy: true})
        .withMessage('Please provide a value for "title"'),
    check('description')
        .exists( { checkNull: true, checkFalsy: true})
        .withMessage('Please provide text for "description"')
], authenticationUser,  asyncHandler(async(req, res)=>{
    
    //attempt to get the validation result from request object
    const errors = validationResult(req);

    //if there are validation errors
    if(!errors.isEmpty()) {
        const errorMessages = errors.array().map(error => error.msg);
        //return the validation errors to the client 
        return res.status(400).json( { errors: errorMessages } );
    }else{
        const courses = await Courses.create(req.body);
        //set status to 201 Created and end response
        return res.status(201).location('courses/' + courses.id).end();
    }
}));

//PUT /api/courses/:id 204 - 
//Updates a course and returns no content
router.put('/courses/:id', [
    check('title')
        .exists( { checkNull: true, checkFalsy: true } )
        .withMessage('Please provide a value for "title"'),
    check('description')
        .exists( {checkNull: true, checkFalsy: true} )
        .withMessage('Please provide a value for "description"'),
    check('userId')
        .exists( {checkNull: true, checkFalsy: true} )
        .withMessage('Please provide a value for "userId"')

], authenticationUser, asyncHandler(async(req,res, next) =>{
    const errors = validationResult(req);

    if(!errors.isEmpty()){
        const errorMessages = errors.array().map(error => error.msg);
        res.status(400).json({ errors: errorMessages });
    } else{
        const user = req.currentUser;
        const course = await Courses.findByPk(req.params.id);
        const users = req.body
        //Only let the user update their course
        if(user.id === course.userId){
            await Courses.update(users);
            res.status(204).end();

        }else{
            res.status(403).json({message: "You cannot change other user's courses"})
        }
    }
   
   
}));

module.exports = router;