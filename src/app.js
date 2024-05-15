// 1) MODULOS DE TERCEROS: Importando los frameworks y Modulos completos 
import express from 'express'
import handlebars from 'express-handlebars' 
import hbs from 'handlebars'
import mongoose from 'mongoose' 
import { Server } from 'socket.io' 
import http from 'http'//Habilitamos el modulo http de NodeJs para hacer el CRUD con sokect.io 
import cookieParser from 'cookie-parser' //Para trabajar las cookies con express() 
import session from 'express-session'//Manejar sessiones y login del lado Servidor 
//import FileStore from 'session-file-store'//Para Almacenar sesiones en archivo (Desactivado)
import sessionMongoStore from 'connect-mongo'//Para Almacenar sesiones en MongoDB 
import passport from 'passport'//Para Hacer Estrategias de Autenticacion

// 2) Importando Rutas Estaticas
import { __dirname } from './utils.js' // MODULOS PROPIOS - Para el Manejo de Rutas Estaticas


// 2.1) Esta Pieza de Codido me Permite Crear Persisten de los Mensajes del CHAT en MongoAtlas
import { MessageController } from './controllers/message.controller.md.js'
// Creando un Nueva Instancia del MessageController
const messageController = new MessageController()


// 3) Importando Rutas Dinamicas
import viewsRouter from './routes/views.routes.js' //Ruta para el Manejo de Plantilla handlebars
import productsRouter from './routes/products.routes.js'//Ruta para el Manejo de products
import cartsRouter from './routes/carts.routes.js'//Ruta para el Manejo de carts
import sessionsRouter from './routes/sessions.routes.js'//Ruta para Manejo de sesiones de usuario
import usersRouter from './routes/users.routes.js'//Ruta para el Manejo de users

 
// 4) Creando la Constante PORT(Puerto) y Asignandole un puerta Conectar
const PORT = 5001


// 5) Conectando con la BD Remota - MONGO ATLAS
const MONGOOSE_URL = 'mongodb+srv://Jean_V2:test_963@cluster0.zqatydb.mongodb.net/ecommerce'


// 6) Creando un Array Vacio para guardar los mensajes enviados por el socketClient  
const message_load = []


// 7) Encapsulamos todo en un Try/Catch
try {

    // 7.1) Intentamos conectar con MONGO ATLAS
    await mongoose.connect(MONGOOSE_URL)

    // 7.2) Inicializando Express 
    // Nota: express solo nos devuelve un Objeto aplication y no Objeto http
    const app = express() 

    // 7.3) Habilitaciones para poder Servir Contenidos de express() y de webSocket() al mismo tiempo
    // - Permitiendo hacer C.R.U.D.con Sokect.i
    const server = http.createServer(app) // Creo un Modulo http y le paso Express/app como parametro 

    // 8) Poniendo a Escuchar el servidor de Express y el Modulo http de Node
    // IMPORTANTE: Ahora podemos Servir Ambos Contenidos   
    server.listen(PORT, () => { console.log(`Backend activo puerto ${PORT} conectado a BBDD`) })

    // 9) Creando una nueva instacia del Socket.io y la pasamos "server" como parametro 
    // Ahora dentro de socketServer estan TODAS configuraciones de los Modulos Express y http de Nodejs
    const io = new Server(server, {
        cors: {
            origin: "*",
            methods: ["PUT", "GET", "POST", "DELETE", "OPTIONS"],
            credentials: false
        }
    })


    // 10) Ponemos al Servidor de socket a escuchar conexiones
    // Nota: Una vez puesta la ruta http://localhost:5000/chat en el navegador
    io.on('connection', socket => {

        // Aca estoy mostrando el ID del Socket-cliente conectado  
        console.log(`nuevo cliente Conectado ID: ${socket.id} `)


        // 11) 1er ESCUCHADOR DEL SERVIDOR ----
        // Aca recibimos La Notificacion del CLIENTE que se CONECTO un nuevo usuario bajo el topico 'user_authenticate'
        socket.on('client:user_authenticate', data => {
            
            // Verificando el usuario que se conecto y me enviaron del cliente
            //console.log(data)

            // Enviando a TODOS los clientes conectados que se Conecto un NUEVO usario al Chat
            //Nota: Aca estamos ejecutano el Evento socket.broadcast.emit
            socket.broadcast.emit('server:broadcast_all', data)

        })

        
        // 12) 2do ESCUCHADOR DEL SERVIDOR ----
        // Nota: Aca estamos Escuchando un Evento
        socket.on('client:chat_message', async data => {

            // Paso 1: Aca mostramos la Data que recibimos del socketClient
            console.log(data)

            // Agregando con Socket.io los Mensajes a la coleccion messages
            const add = await messageController.addMessage(data)

            //Guardando en un array todos los productos recibido del 'client:message'
            message_load.push(add)
            
            //Paso 2: Enviamos la lista de mensajes cargadoe en el Chat hasta el momento
            // Nota: Aca estamos ejecutano el Evento .emit (emitir - enviar)
            io.emit('server:messageLogs', message_load)
            
            
        })


    })


    // 13) Habilitadon a Express para manejar paquetes json correctamente
    app.use(express.json())

    // 14) Habilitando a express para trabajar con urls (peteciones req y res)
    app.use(express.urlencoded({ extended: true }))

    // 15) Habilitatndo a Express para crear y poder trabajar con cookies del lado del cliente 
    app.use(cookieParser('secretkeyAbc123')) // A Partit de ahora podemos INTERPRETAR Y PASEAR COOKIES

    
    // 16) Habilitamos el Modulo de session para usarlo con express
    app.use(session({

    
        //Instancia para almacenar datos de sesión en MongoDB - Usando el MODULO sessionMongoStore
        // Si en cambio preferimos guardar a MongoDB, utilizamos connect-mongo,
        store: sessionMongoStore.create({ mongoUrl: MONGOOSE_URL, mongoOptions: {}, ttl: 60, clearInterval: 3600 }),
        //Especifica almacenamiento para las sesiones en MONGODB

        // Usando los Campos pre-establecidos en el Objeto options incluidos en el Modulo express-session 

        secret: 'secretKeyAbc123', // Firmamos la cookie.sid evitar usarlo si el cliente la modifica
        resave: false, // Permite tener la session Activa a pesar de estar inactiva
        saveUninitialized: false // Si esta en true guarda(memoria o archivo...etc) la session aunque NO se alla modificado nada en el req.session ... Si le pongo false NO la almacena hasta cambie los datos en el login 
        

    })) // A Partit de ahora podemos GUARDA INFORMACION de sesiones DEL CLIENTE DEL LADO DEL SERVIDOR 


    // 17) Inicializando - Habilitamos el Modulo "passport" en la app para poder Hacer Estrategias de Autenticacion 
    app.use(passport.initialize()) // Estamos avisando que queremos usar el modulo passport 
    app.use(passport.session())// Entrelazando-Integrando Modulo passport al Modulo de session que Creamos **Punto 17)


    // 18) Habilitando/Inicializando el modulo HANDLEBARS
    app.engine('handlebars', handlebars.engine())
    app.set('views', `${__dirname}/views`)
    app.set('view engine', 'handlebars')
    hbs.registerHelper('eq', (a, b) => a === b)//Habilitatando la validacion de Strin en handlebars 

    // 19) Inicializando Las Rutas para la API
    app.use('/', viewsRouter) // Para el renderizado de Plantillas
    app.use('/api/carts', cartsRouter) // Para la coleccion carts
    app.use('/api/products', productsRouter) // Para la coleccion products 
    app.use('/api/sessions', sessionsRouter) // Es una ruta creada para el manejo de sesion de usuario
    app.use('/api/users', usersRouter) // Para la coleccion users 
    
    // 20)RUTAS ESTATICAS para mostrar del lado del cliente los contenidos Estaticos que estan en la carpeta PUBLIC
    app.use('/static', express.static(`${__dirname}/public`)) 

} catch (err) {

    // Manejando el Error 
    console.log(`No se puede conectar con el servidor de bbdd (${err.message})`)

}