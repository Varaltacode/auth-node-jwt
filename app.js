require('dotenv').config()
const express = require('express')
const mongoose = require('mongoose')
const bcrypt = require('bcrypt')
const jwt = require('jsonwebtoken')
const app = express()
const db = require('./connectDB')
const User = require('./models/User')

//config JSON response
app.use(express.json())

// public route
app.get('/', (req, res)=> {
    return res.json({msg: 'home page'}) 
})

// private route
app.get('/user/:id', checkToken, async(req,res)=>{
    const id = req.params.id
    // check  if user exists
    const user = await User.findById(id, '-password')
    if(!user){
        return res.status(404).json({msg: 'Usuário não encontrado'})
    }
    res.status(200).json(user)
})

function checkToken(req, res, next){
    const authHeader = req.headers['authorization']
    const token = authHeader && authHeader.split(" ")[1]
    if(!token){
        return res.status(401).json({msg: 'Acesso negado'})
    }

    try{
        const secret = process.env.SECRET
        jwt.verify(token, secret)
        next()
    }catch(err){
        console.log(err)
        return res.status(500).json({msg: 'Algo deu errado'})
    }
}

// register user
app.post('/auth/register', async (req, res)=>{
    const {name, email, password, confirmpassword} = req.body
    // validations
    if(!name){
        return res.status(422).json({msg: 'O nome é obrigatório'})
    }
    if(!email){
        return res.status(422).json({msg: 'O email é obrigatório'})
    }
    if(!password){
        return res.status(422).json({msg: 'A senha é obrigatória'})
    }
    if(!confirmpassword){
        return res.status(422).json({msg: 'A confirmação de senha é obrigatória'})
    }

    if(password !== confirmpassword){
        return res.status(422).json({msg: 'As senhas não coincidem'})
    }
    // check if user exists
    const userExists = await User.findOne({email: email})
    if(userExists){
        return res.status(422).json({msg: 'Usuário já existe, utilize outro email'})
    }
    // create password
    const salt = await bcrypt.genSalt(10)
    const hashedPassword = await bcrypt.hash(password, salt)
    // create user
    const user = new User({
        name,
        email,
        password: hashedPassword
    })

    try{
        await user.save()
        res.status(201).json({msg: 'Usuário criado com sucesso'})
    }catch(err){
        console.log(err)
        res.status(500).json({msg: 'Aconteceu um erro, tente novamente mais tarde'})
    }
})

// login
app.post('/auth/login', async(req, res)=>{
    const {email, password} = req.body
    // validations
    if(!email){
        return res.status(422).json({msg: 'Email obrigatório'})
    }
    if(!password){
        return res.status(422).json({msg: 'Senha obrigatória'})
    }
    // check if user exists
    const user = await User.findOne({email: email})
    if(!user){
        return res.status(404).json({msg: 'Usuário não encontrado'})
    }
    // check  if password match
    const passwordCheck = bcrypt.compare(password, user.password)
    if(!passwordCheck){
        return res.status().json({msg: 'Senha inválida'})
    }

    try{
        const secret = process.env.SECRET
        const token = jwt.sign({
            id: user._id
        }, secret)
        res.status(200).json({msg: 'Autenticado com sucesso', token})
    }catch(err){
        console.log(err)
        return res.status(500).json({msg: 'Algo deu errado, tente novamente'})
    }
})

app.listen(3000, ()=>{
    db.connect()
    console.log('working')
})
