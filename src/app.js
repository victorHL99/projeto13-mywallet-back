import express, {json} from 'express';
import chalk from 'chalk';
import cors from 'cors';
import dotenv from 'dotenv';
import {MongoClient} from 'mongodb';
import joi from 'joi';
import bcrypt from 'bcryptjs';
import {v4} from 'uuid';
import dayjs from 'dayjs';

const app = express();
app.use(cors());
app.use(json());
dotenv.config();

let dataBase = null;
const mongoClient = new MongoClient(process.env.MONGO_URL)
const promise = mongoClient.connect();
promise.then(response => {
    dataBase = mongoClient.db("my_wallet");
    console.log(chalk.green.bold("Banco de dados conectado")); 
});
promise.catch(erro => {
    console.log(chalk.red.bold("Banco de dados não conectado"));
})



app.post("/", async (req, res) => {
    const { email, senha } = req.body;

    const usuario = {
        email,
        senha
    }

    const usuarioSchema = joi.object({
        email: joi.string().email().required(),
        senha: joi.string().alphanum().required().min(6).max(20)
    });

    const validarUsuario = usuarioSchema.validate(usuario, {abortEarly: false});

    if(validarUsuario.error){
        res.status(422).send(validarUsuario.error.details.map(descricao => descricao.message));
        return;
    }

    try{
        const validarEmail = await dataBase.collection("usuarios").findOne({email});
        if(validarEmail && bcrypt.compareSync(senha, validarEmail.senha)){
            const token = v4();
            res.status(200).send(token);
            await dataBase.collection("registros").insertOne({token, IdUsuario: validarEmail._id});
            await dataBase.collection("logs").insertOne({token, IdUsuario: validarEmail._id, dia: dayjs().format("DD/MM")});
        } else {
        res.status(404).send("Usuário não encontrado");
        return;
        }
    }
    catch {
        res.status(500).send("Erro no servidor");
    }

})

app.post("/registrar", async (req, res) => {
    const {nome, email, senha, confirmarSenha} = req.body;
    const novoUsuario = {
        nome,
        email,
        senha,
        confirmarSenha
    }

    const novoUsuarioSchema = joi.object({
        nome: joi.string().required(),
        email: joi.string().email().required(),
        senha: joi.string().alphanum().required().min(6).max(20),
        confirmarSenha: joi.string().alphanum().required().min(6).max(20)
    })

    const validarNovoUsuario = novoUsuarioSchema.validate(novoUsuario);

    if(validarNovoUsuario.error){
        res.status(422).send(validarNovoUsuario.error.details.map(descricao => descricao.message));
        return;
    }

    try {
        const senhaCriptografada = bcrypt.hashSync(senha, 10);
        const validarCadastro = await dataBase.collection("usuarios").findOne({email});
        if(validarCadastro){
            res.status(409).send("Usuário já cadastrado");
            return;
        }

        if(senha !== confirmarSenha){
            res.status(409).send("Senhas não conferem");
            return;
        } else {
            delete novoUsuario.confirmarSenha;
        }

        await dataBase.collection("usuarios").insertOne({...novoUsuario, senha: senhaCriptografada});
        res.status(201).send("Usuário cadastrado com sucesso");
    }
    catch {
        res.status(500).send("Erro no servidor");
    }
})

app.get("/paginaPrincipal", async (req, res) => {
    const {authorization} = req.headers;
    const token = authorization?.replace("Bearer ", "").trim();

    if(!token){
        res.status(401).send("Não autorizado");
        return;
    }

    const logs = await dataBase.collection("logs").findOne({token});
    if(!logs){
        res.status(401).send("Não autorizado");
        return;
    }

    const usuario = await dataBase.collection("usuarios").findOne({_id: logs.IdUsuario});
    if(!usuario){
        res.status(404).send("Usuário não encontrado");
        return;
    }

    const registros = await dataBase.collection("registros").findOne({_id: logs.IdUsuario});

    delete usuario._id;
    delete usuario.senha;

    res.status(200).send({usuario, registros});
})

app.post()



app.listen(process.env.PORTA, () => {
    console.log(chalk.blue.bold("Servidor iniciado na porta 5000"))
});