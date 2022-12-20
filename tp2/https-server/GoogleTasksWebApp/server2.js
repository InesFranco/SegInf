//VERSION WITHOUT AXIOS

const PORT = 4001

const CLIENT_ID = "924357387713-oqrbsgbes3064k8os19k40b7tceu218g.apps.googleusercontent.com"

const CLIENT_SECRET = "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"

const CALLBACK = 'redirect'

const express = require('express');
const fs = require('fs');
const casbin = require('casbin');
const jwt = require('jsonwebtoken');
const passport = require('passport');
const app = express();

const request = require('request')


/** USER INFO **/
 
let userInfo = {}

function createUser(username, password){
    const user = {}
    user.id = username
    user.auth = password
    userInfo[user.id] = user
    return Promise.resolve(user)
}

function getUser(username){
    return Promise.resolve(userInfo[username])
}

/** ---- ---- **/




app.set('view engine', 'hbs')

app.use(express.urlencoded({ extended: true }))
app.use(require('cookie-parser')())
app.use(require('express-session')({secret: 'keyboard-cat', resave: true, saveUninitialized: true}))
app.use(passport.initialize())
app.use(passport.session())
app.use(express.static(__dirname + '/public'))

passport.serializeUser((user, done) => {
    done(null, user.id)
})

passport.deserializeUser((user, done) => {
    getUser(user)
    .then(username => done(null, username))
    .catch(err => done(err))
})

let enforcerPromise = casbin.newEnforcer(
    casbin.newModel(fs.readFileSync("C:\\isel\\2223i\\SEG-INF\\Trabalhos\\SegInf\\tp2\\https-server\\GoogleTasksWebApp\\rbac_model.conf", 'utf-8')),
    new casbin.StringAdapter(fs.readFileSync("C:\\isel\\2223i\\SEG-INF\\Trabalhos\\SegInf\\tp2\\https-server\\GoogleTasksWebApp\\rbac_policy.csv", 'utf-8'))
);

async function enforce(sub, obj, act){
    const enforcer = await enforcerPromise;
    return await enforcer.enforce(sub, obj, act);
}




app.get('/', (req, res) => {
    res.render('login')
})


app.get('/login', (req, res) => {

    let state = (Math.random() + 1).toString(32)
    res.cookie('state', state)

    res.redirect
    (
        302,

        'https://accounts.google.com/o/oauth2/v2/auth?'
        + 
        'client_id=' + CLIENT_ID 
        + '&' +
        'scope=openid%20email%20https://www.googleapis.com/auth/tasks&'
        + 
        'state' + state
        + '&' +
        'response_type=code&'
        +
        'redirect_uri=http://localhost:4001/' + CALLBACK)
})

app.get('/' + CALLBACK, (req, res) => {
    if(req.originalUrl.split('=')[1].split('&')[0] != req.cookies.state){ //---
        res.redirect('/error')
        return
    }

    request
        .post(
            {
                url: 'https://www.googleapis.com/oauth2/v3/token',
                form: {    
                    code: req.query.code,
                    client_id: CLIENT_ID,
                    client_secret: CLIENT_SECRET,
                    redirect_uri: 'http://localhost:4001' + CALLBACK,
                    grant_type: 'authorization_code',
                }
            },
            function(err, response, body) {
                if(err) response.redirect('/error')

                const json = JSON.parse(body);
                const jwt_payload = jwt.decode(json.id_token);

                createUser(jwt_payload.email, jwt_payload.access_token)
                .then(user => {
                    req.logIn(user, err =>{
                        if(err) res.redirect('/error')
                        res.redirect('/tasks')
                        res.end()
                    })
                })
            }
        );
})

app.get('/tasks', (req, res) => {

    if(!req.user){
        res.redirect('/notauthorized')
    } 
    else 
    {
        try{
            request({
                host: 'https://tasks.googleapis.com',
                path: '/tasks/v1/users/@me/lists',
                uri: 'https://tasks.googleapis.com/tasks/v1/users/@me/lists',
                method: 'GET',
                headers: {
                    Authorization: 'Bearer ' + req.user.auth,
                    'Content-Type': 'application/json'
                }
            }, 
                function(err, response, body){
                 
                    if(err) response.redirect('/error')   
                    const json = JSON.parse(body);

                    res.render('tasks', {'list': json.items})
                })

        } catch(err){res.redirect('/error')}
    } 
})

//free, premium, admin
app.get('/tasks/:id', (req, res) => {

    if(!req.user){
        res.redirect('/notauthorized')
    } 

    enforce(req.user.id, 'task', 'GET').then(res2 => {
        if(!res2) res.redirect('/notauthorized')
        else {
            try{
                request({
                    host: 'https://tasks.googleapis.com',
                    path: '/tasks/v1/lists/' + req.params.id + '/tasks',
                    uri: 'https://tasks.googleapis.com/tasks/v1/lists' + req.params.id + '/tasks',
                    method: 'GET',
                    headers: {
                        Authorization: 'Bearer ' + req.user.auth,
                        'Content-Type': 'application/json'
                    }
                },
                    function(err, response, body){
                        
                        if(err) res.redirect('/error')
                        
                        const json = JSON.parse(body);

                        res.render('task', {'list': json.items})
                    }
                )
                

            }catch(err){
                console.log(err)
                res.redirect('/error')
            }
        }
    })

})

//premium, admin - ENFORCE
app.post('/tasks/:id', async (req, res) => {
    if(!req.user){
        res.redirect('/error')
        return
    }
    enforce(req.user.id, 'task', 'POST').then(res2 => {
        if (!res2) res.redirect('/notauthorized')
        else {
            try {
                request({
                    host: 'https://tasks.googleapis.com',
                    path: `/tasks/v1/lists/${req.params.id}/tasks`,
                    uri: `https://tasks.googleapis.com/tasks/v1/lists/${req.params.id}/tasks`,
                    method: 'POST',
                    headers: {
                        Authorization: 'Bearer ' + req.user.auth,
                        'Content-Type': 'application/json'
                    }
                },
                    function(err, response, body){
                        
                        if(err) res.redirect('/error')
                        
                        const json = JSON.parse(body);

                        res.redirect(`/tasks/${req.params.id}`)
                    })
            }catch(err){
                console.log(err)
                res.redirect('/error')
            }
        }
    })
})

//admin
app.get('/admin', (req,res) => {

    if(!req.user){
        res.redirect('/notauthorized')
        return
    }

    enforce(req.user.id, 'secret', 'GET').then(res2 => {
        if(!res2) res.redirect('/notauthorized')
        else {
            try{
                res.render('admin')
            }catch(err){
                res.redirect('/error')
            }
        
        }
    })
})

app.post('/admin', (req, res) => {

    if(!req.user){
        res.redirect('/notauthorized')
        return
    }

    enforce(req.user.id, 'secret', 'GET').then(res2 => {
        if(!res2) res.redirect('/notauthorized')
        else {
            try{
                fs.appendFileSync('rbac_policy.csv', 'g, ' + req.body.user + ', ' + req.body.role + '\n');
                enforcerPromise = casbin.newEnforcer(
                    casbin.newModel(fs.readFileSync("C:\\isel\\2223i\\SEG-INF\\Trabalhos\\SegInf\\tp2\\https-server\\GoogleTasksWebApp\\rbac_model.conf", 'utf-8')),
                    new casbin.StringAdapter(fs.readFileSync("C:\\isel\\2223i\\SEG-INF\\Trabalhos\\SegInf\\tp2\\https-server\\GoogleTasksWebApp\\rbac_policy.csv", 'utf-8'))
                )
                res.redirect('/admin')
            }catch(err){
                res.redirect('/error')
            }
        }
    })
})

app.get('/error', (req, res) => {
    res.render('error')
})

app.get('/notauthorized', (req, res) => {
    res.render('notauthorized')
})

app.get('/out', (req, res) => {
    if(!req.user){
        res.redirect('/error')
        return
    }
    res.logout(req.user, err => {
        if(err) return next(err);
        res.redirect("/")
    })
})

app.get('*', (req, res) => {
    res.render('error')
})

app.listen(PORT, (err) => {
    if (err) {
        return console.log('Unexpected ERROR!', err)
    }
    console.log(`Listening on ${PORT}`)
});