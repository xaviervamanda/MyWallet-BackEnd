import express from "express";
import cors from "cors";
import { MongoClient, ObjectId } from "mongodb";
// uuid para criação de strings aleatórias para serem usadas como tokens
import {v4 as uuid} from "uuid";
import dotenv from "dotenv";
import bcrypt from "bcrypt";
import joi from "joi";

const app = express();

app.use(express.json());
app.use(cors());
dotenv.config();

const mongoClient = new MongoClient(process.env.DATABASE_URL);

try{
    await mongoClient.connect();
    console.log("MongoDB conectado!");
    
} catch (err){
    console.log(err.message)
}

const db = mongoClient.db();


const userSchema = joi.object({
    name: joi.string().required(),
    email: joi.string().email().required(),
    password: joi.string().min(3).required()
});

const transactionSchema = joi.object({
    token: joi.string().required(),
    value: joi.string().pattern(/^\d+(\.\d{1,2})?$/).required(),
    description: joi.string().required(),
    type: joi.string().valid("incoming", "outgoing").required()
});

app.post ("/login", async (req, res) => {
    const {email, password} = req.body;

    const userSchema = joi.object ({
        email: joi.string().email().required(),
        password: joi.string().required()
    });

    const validation = userSchema.validate({email, password});
    if (validation.error) return res.sendStatus(422);

    const token = uuid();

    try{
        const user = await db.collection("users").findOne({email});
        if (!user) return res.sendStatus(404);
        if (!bcrypt.compareSync(password, user.password)) return res.sendStatus(401);
        await db.collection("sessions").insertOne({userId: user._id, token});
        return res.status(200).send({token});
    } catch (err) {
        return res.status(500).send(err.message);
    }
});

app.post ("/sign-up", async (req, res) => {
    const {name, email, password} = req.body;

    const validation = userSchema.validate({name, email, password}, {abortEarly: false});
    if (validation.error){
        const errors = validation.error.details.map((detail) => detail.message);
        return res.status(422).send(errors);
    }
    
    const encryptedPassword = bcrypt.hashSync(password, 10);

    try{
        const user = await db.collection("users").findOne({email});
        if (user) return res.sendStatus(409);
        await db.collection("users").insertOne({name, email, password: encryptedPassword});
        return res.sendStatus(201);

    } catch (err){
        return res.status(500).send(err.message);
    }
});

app.post ("/transaction/:type", async (req, res) => {
    const {authorization} = req.headers;
    let {value, description} = req.body;
    const {type} = req.params;
    const token = authorization?.replace("Bearer ", "");
    
    if (!token) return res.sendStatus(401);

    const validation = transactionSchema.validate({token, type, value, description}, {abortEarly: false});
    if(validation.error){
        const errors = validation.error.details.map(detail => detail.message);
        return res.status(422).send(errors);
    }

    value = parseFloat(value);
    value = value.toFixed(2);
    
    try{
        
        const session = await db.collection("sessions").findOne({token});
        
        if (!session) return res.sendStatus(401);
        
        const user = await db.collection("users").findOne({_id: session.userId});
        if (!user) return res.send(401);
        await db.collection("transactions").insertOne({value, description, type, userId: session.userId});
        return res.sendStatus(200);
    } catch (err){
        return res.status(500).send(err.message);
    }

});




const PORT = 5000;
app.listen (PORT, () => console.log("Servidor rodando na porta 5000"));