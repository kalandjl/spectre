import { Request, Response, NextFunction } from "express"
import { setDoc } from "./lib/db/postgres"
import UploadRouter from "./routes/http/UploadRouter"
const express = require('express')
const app = express()
const port = 4000

const cors = require("cors")


app.use(express.json())

const corsOptions = {
  origin: 'http://localhost:3000' 
}

app.use(cors(corsOptions))

app.get('/', (req: Request, res: Response) => {
  res.send('Hello World!')
})

// CSV upload endpoint
app.post('/api/upload', UploadRouter)  

