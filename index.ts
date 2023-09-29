var morgan = require('morgan');
import redisClient from "./utils/redisHelper";
import path from "path";
import {SequelizeDbHelper} from "../sequlizeDB"
const config = require("config")
const express = require('express')
const bodyParser = require('body-parser')
const cors = require("cors");
const cookieParser = require("cookie-parser");
require('dotenv').config()
import eventEmitter from "./utils/event";
import userRoute from "./components/users";
import adminRoute from "./components/admin";
import corsOptions from "./utils/corsOptions";
import {NextFunction, Request, Response} from "express";
import { User } from './components/users/models/userModel';
import { Admin } from "./components/admin/models/admin";
import { Currency } from "./components/admin/models/currency";
import { RecoverWord } from "./components/admin/models/RecoverWord"; 
import { userRecoverWord } from "./components/users/models/userRecoverWord";
import { Ticket } from "./components/users/models/ticket";
import { Wallet } from "./components/users/models/wallet";
import { Chat } from "./components/users/models/chat";
import { Address } from "./components/users/models/address";
import { Notification } from "./components/users/models/notification";
import { Ticketchat } from "./components/users/models/ticketChat"
import { NewAddress } from "./components/users/models/newAddress";
import { sendHistory } from "./components/users/models/sendHistory";
import { userCurrency } from "./components/users/models/userCurrency";
import { TokenCurrency } from "./components/users/models/TokenCurrency";
import { userTokenCurrency } from "./components/users/models/userTokenCurrency";
const admin = require("firebase-admin")
const userMap: any = {};
const userMapMobile: { [key: string]: string } = {}
let connectedUsers: any = {};

let sequelizeDbHelper = SequelizeDbHelper.getInstance()
let sequelizeClient = sequelizeDbHelper.getSequelizeClint()

express.application.prefix = express.Router.prefix = function (path: any, configure: any) {
    var router = express.Router();
    this.use(path, router);
    configure(router);
    return router;
};

const app = express()

app.set('views', path.join(path.dirname(__dirname)));
app.set('view engine', 'ejs');

app.use(function (req: Request, res: Response, next: NextFunction) {
    res.header("Access-Control-Allow-Origin", "*");
    res.header(
        "Access-Control-Allow-Headers",
        "Origin, X-Requested-With, Content-Type, Accept"
    );
    next();
});
app.use(cors(corsOptions))
app.use(cookieParser());

// app.use(bodyParser.json({limit: '50mb'}))
// app.use(bodyParser.urlencoded({limit: '50mb', extended: true}))
// app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());


app.set('views', path.join(__dirname+'/components/users', 'views'));
app.set('view engine', 'ejs');


// app.use('/uploads', express.static(path.join(__dirname, '/uploads')))
app.use('/image', express.static(path.join(__dirname,'/uploads/images')))
// app.use('/document', express.static(path.join(__dirname,'/uploads/files')))
// app.use('/video', express.static(path.join(__dirname,'/uploads/videos')))


app.use(morgan('dev', {skip: (req: any, res: any) => process.env.NODE_ENV === 'production'}));
app.set('eventEmitter', eventEmitter)

app.prefix('/user', (route: any) => {
    userRoute(route)
})

app.prefix('/admin', (route: any) => {
    adminRoute(route)
})

const http = require('http');
const server = http.createServer(app);
// const {Server} = require("socket.io");
// const io = new Server(server);
import log4js from "log4js";
const logger = log4js.getLogger();

log4js.configure({
    appenders: {
        everything: {
            type: 'dateFile',
            filename: './logger/fex.log',
            maxLogSize: 10485760,
            backups: 3,
            compress: true
        }
    },
    categories: {
        default: { appenders: ['everything'], level: 'debug' }
    }
});

process.on('uncaughtException', (error, origin) => {
    console.log('----- Uncaught exception -----')
    console.log(error)
    console.log('----- Exception origin -----')
    console.log(origin)
})

process.on('unhandledRejection', (reason, promise) => {
    console.log('----- Unhandled Rejection at -----')
    console.log(promise)
    console.log('----- Reason -----')
    console.log(reason)
})

admin.initializeApp({
    credential: admin.credential.cert({
        
        "type": "service_account",
        "project_id": "fex-wallet",
        "private_key_id": "e0bf7c5fc51aa34a0669b65675c26847f2f33577",
        "private_key": "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7WnbR18fAwn7i\nd2Q+0HnzuZ/tzjjMXgV+WDlbiX1rCjMC2Ed62yjH5edKxpgUZkf8fODbUEtY/NY8\noiwgKBtfWzXZ87cykjubdOa7E7pnQkbhUZF7G0IT1sQ8XSAGo3skHwdLXARoYVin\nNWO8P8amN7jYNXYgio1O5WB9Td+4Zcr03TrBThmiaqLQ4Dm7xTVk4AzOiSbZEavy\n1PVh4HqLGlfFmGHt8gI+VljpiR1XJ1s2ViOD8aekWL48Emof/sRauzI7hjdIgwEq\nX9zdprM/nGBh3JRheah9zJfXvyh2YuIx2yBe/SXvApzqbf5l8jCZrPddQbGwF02t\nMLINC83LAgMBAAECggEAGB1rSNRI4k9GjLjIXutvnwboBnByUB/T/jC15UnbqlDs\nQvP6s14NMDmv3SiVv55wqpeaS7BYmnIk0zYejt8KsunnExAzJt+6q2ZPIopGBm95\n9xuMKbfW9/2/UXO9IQ2e1oXl5vXHnXXWNuOA3GSrGY73jGDJPSQITzzoAAjrgGzl\nYa2QiBl0cdwRbZ68Eel1o6JUWbYj3bjR6l7cxeMArdSX2Xp7tKcg9s7+ia3fxHGM\nOoRT0ak8WR74dXUiKwSFJRoGfqzN5lzUYORkIx1aNRQrn96lw9LE+X1FBxzkki+f\nYf6kb0mz73j0Fii44bapUwsy1t8VNnoYsH7Y3hiVDQKBgQDeb/o2x8lncwyOtD0S\nrnET5aBzplcrv6fMvq2/XW94jIK8YSZvxxVRhO8DcAZ68PUznsuoLicvjyRuNyYp\n3SgbKz3/Cy0DF1RnXkB/Lz3e0W1N4nBxGnOE1+9TsoAag4k6FuthWCioJZazbc+/\nJBuTvrNm+o8HhDLv3F9AYotY3QKBgQDXn05pFsoR8DptGfoX9vYYofPGQLd2wZDZ\ngfjVwuWOmf7n6ZoLjIR7AqJtDLsVSW6C7/FZ4HqzAfghVMP11+bgfazjiN1CuUU3\nxEy8NwVikSngaEI5JN3IWnzhcUFPUNEUztaa5kr6Y92UFZPaCJnPOgoAPvNNo4eG\n7zIAB6gCxwKBgQCUknqwKFXQMTpL/vtkBPwmbBP16z8CS6tKyHnI/iG8hS21obZI\nptMIdiAnTaYma9d7uS8SkHFABP4yV8e34q4tJ37rYY2ZKPYJbRzrVqSetYeqo/qy\nsRZDvu9uGiYSj5UTJcfmZzoQxbqY8ln2s6lvz8qImAb84EIdkDZXDPtCSQKBgB2o\n/Uk5aEx1ZiQR2bQoNYwH4xeXWWVNlRZGaatF5vvptQXDvXvvNV4Sa7Nid+2irz/1\nr5Z0aYxsLeyv01DjBRBGWVznO8Bs6deU+hU94FDBtSf4T3u61YM0506/nINDk68w\nEJc4LIIq8JTpLvBkFHxL+Io2HpPEdeUazB7y7qqLAoGAJ0/55VjaaXso6+9TP60q\nUEmTkC8SOlgSfQj2Ky55KorT25UCsOLbcqeW4qX6tcbiguVakkkNMJ2KAgtu+nbP\n9yBRWPdgSXPvlwAbNlZ+tF9mBLmBuRp+cHTlon+7bvFu5IVjDIIm/+sZxcjWaFu+\nrAJi727dHaRfdWNnPU1k6WA=\n-----END PRIVATE KEY-----\n",
        "client_email": "firebase-adminsdk-uralq@fex-wallet.iam.gserviceaccount.com",
        "client_id": "109765062550025944894",
        "auth_uri": "https://accounts.google.com/o/oauth2/auth",
        "token_uri": "https://oauth2.googleapis.com/token",
        "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
        "client_x509_cert_url": "https://www.googleapis.com/robot/v1/metadata/x509/firebase-adminsdk-uralq%40fex-wallet.iam.gserviceaccount.com"
          
    })
})

const firebaseMessaging = admin.messaging()


import winston, { format, transports } from 'winston';
import DailyRotateFile from 'winston-daily-rotate-file';

// Create a logs directory if it doesn't exist
const logDirectory = path.join(__dirname, 'logs');

// Define log format
const logFormat = format.printf(({ level, message, timestamp }) => {
    return `${timestamp} [${(level as string | undefined)?.toUpperCase()}]: ${message}`;
  });
  
  // Create a logger instance
  const transaction_logger = winston.createLogger({
    format: format.combine(
      format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
      logFormat
    ),
    transports: [
      // DailyRotateFile transport for storing logs in a file with day-wise rotation
      new DailyRotateFile({
        dirname: logDirectory,
        filename: 'application-%DATE%.log',
        datePattern: 'YYYY-MM-DD',
        zippedArchive: true,
        maxSize: '20m',
        maxFiles: '30d',
      }),
    ],
  })
const IP = require('ip');
server.listen(config.get("PORT"), () => {
    console.log(`⚡️[NodeJs server]: Server is running at http://${IP.address()}:${config.get("PORT")}`)

    sequelizeClient.authenticate().then(async () => {
        console.log('Connection has been established successfully.')
        // ORM Relation with DB tables
        sequelizeClient.addModels([
            User,
            Admin,
            Currency,
            RecoverWord,
            userRecoverWord,
            Ticket,    
            Wallet,
            Chat,
            Notification,
            Ticketchat,
            Address,
            NewAddress,
            sendHistory,
            userCurrency,
            TokenCurrency,
            userTokenCurrency
        ])
        
        userRecoverWord.belongsTo(User, {as: "user", foreignKey: "user_id", targetKey: "id"})
        Ticket.belongsTo(User, {as: "user",foreignKey: "user_id",targetKey: "id"});
        Wallet.belongsTo(User, {as: "User",foreignKey: "user_id"});
        Chat.belongsTo(User,{as:"user",foreignKey:"sender_id",targetKey:"id"})
        User.hasOne(Wallet, {
            as:"wallet",
            foreignKey: 'user_id',
            // sourceKey: 'id'
          });
        Chat.belongsTo(Admin,{as:"Admindata",foreignKey:"receiver_id",targetKey:"id"})
        // Admin.belongsTo(Chat,{as:"admin",foreignKey:"receiver_id",targetKey:"id"})
        Wallet.belongsTo(Currency,{as:"Currencydata",foreignKey:"currency_id",targetKey:"id"})  
        Ticketchat.belongsTo(Ticket,{as:"Ticketdata",foreignKey:"ticket_id",targetKey:"id"})  
        Ticket.hasMany(Ticketchat,{as:'TicketChatData',foreignKey:'ticket_id',sourceKey:'id'})
        userRecoverWord.belongsTo(Wallet, {as: "Wallet",foreignKey: "wallet_id"});
        Notification.belongsTo(User,{as:"userdata",foreignKey:"user_id"})  

        Address.belongsTo(User, {as: "user",foreignKey: "user_id",targetKey: "id"});
        Address.belongsTo(Wallet, {as: "Wallet",foreignKey: "wallet_id",targetKey:"id"});
        Address.belongsTo(Currency,{as:"Currency",foreignKey:"currency_id",targetKey:"id"})

        Wallet.hasOne(Address,{as:"Addressdata",foreignKey:"wallet_id"})  

        sendHistory.belongsTo(User, {as: "userData",foreignKey: "sender_id",targetKey: "id"});
        sendHistory.belongsTo(Currency, {as: "currencyData",foreignKey: "currency_id",targetKey: "id"});

        // userCurrency.belongsTo(User,{as:"userData", foreignKey:"user_id"})
        Currency.hasMany(userCurrency,{as:'userCurrencydata',foreignKey:'currency_id',sourceKey:'id'})
        userCurrency.belongsTo(Currency,{as:'currencyData',foreignKey:'currency_id',targetKey: 'id'})
        // Currency.belongsTo(userCurrency,{as:'currencydata',foreignKey:'currency_id'})

        TokenCurrency.belongsTo(Currency,{as:'currencyData',foreignKey:'currency_id',targetKey: 'id'})

        TokenCurrency.belongsTo(Currency,{as:'CurrencyData',foreignKey:'token_currency_id',targetKey: 'id'})

        Currency.hasMany(TokenCurrency,{as:'tokenCurrencyData',foreignKey:'currency_id',sourceKey:'id'})

        userTokenCurrency.belongsTo(TokenCurrency,{as:'TokenCurrencyData',foreignKey:'token_currency_id',targetKey:'id'})
        userTokenCurrency.belongsTo(Currency,{as:'Currency_Data',foreignKey:'token_currency_id',targetKey:'id'})
        TokenCurrency.hasMany(userTokenCurrency, {as: 'userTokenCurrencyData', foreignKey: 'token_currency_id',  sourceKey:'id'});

        await sequelizeClient.sync()


    }).catch((reason: any) => console.log('[Sequelize Error] ', reason))
    redisClient.on('error', (err: any) => console.log('Redis Client Error', err));
    // io.on('connection', connectionHandler);

});

export {
    // io, 
    userMap,
    userMapMobile,
    connectedUsers,
    firebaseMessaging,
    transaction_logger
}
//  "ROUTE_URL": "http://192.168.0.156:7009",