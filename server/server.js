import express from 'express';
import cors from 'cors';
import morgan from 'morgan';
import connect from './database/connect.js';
import router from './router/route.js';

const app = express();

/** middlewares */
app.use(express.json());
app.use(cors());
app.use(morgan());
app.disable('x-powered-by'); //less hackers know about our stack

const PORT = 8080;

/** HTTP GET request */

app.get('/', (req, res) =>{
    res.status(201).json("Home GET Request");
});

/** api routes */
app.use('/api', router)

/** start server  only when we have valid connection */
connect().then(()=>{
    try{
        app.listen(PORT, ()=>{
            console.log(`Server running on http://localhost:${PORT}`)
        })
    }catch (error) {
        console.log('Cannot connect to the server')
    }
}).catch (error => {
    console.log("Invalid database connection...!")
})