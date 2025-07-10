"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
var UploadRouter_1 = require("./routes/http/UploadRouter");
var express = require('express');
var app = express();
var port = 4000;
var cors = require("cors");
app.use(express.json());
var corsOptions = {
    origin: 'http://localhost:3000'
};
app.use(cors(corsOptions));
app.get('/', function (req, res) {
    res.send('Hello World!');
});
// CSV upload endpoint
app.post('/api/upload', UploadRouter_1.default);
