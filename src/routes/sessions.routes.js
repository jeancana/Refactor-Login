import { Router } from 'express'
import { UsersController } from '../controllers/user.controller.mdb.js'


// LLAMANDO A LA FUNCIONES HELPERS QUE CREAMOS CON EL MODULO "bcrypt"
import { createHash, isValidPassword } from '../utils.js'// Otra forma de importa todo junto

// Para Trabajar la Autenticacion con Modulo Passport
import initPassport from '../config/passport.config.js' // Importo el Metodo initPassport creado en la carpete config

// Llamando a las funciones creadas en la carpeta Utils para trabajar con JWT
import { generateToken, authToken } from '../utils.js'

initPassport() // inicializando instancia de la estrategia local


const router = Router()
const userController = new UsersController()

// **** Middleware de autorización de un Usuario con ROLE de admin - SOlO SIRVE PARA express-session ****
// En este caso, si el usuario es admin, llamanos a next, caso contrario
// devolvemos un error 403 (Forbidden), no se puede acceder al recurso.
// Si ni siquiera se dispone de req.session.user, directamente devolvemos error de no autorizado.
const auth = (req, res, next) => {

    try {
        // Autenticamos que el objeto user este autozido
        if (req.session.user) {

            // Al ser un usuario valido verificamos si su rol es Admin
            if (req.session.user.role == 'admin') {

                next()

                // Sino esta Autorizado Admin devolvemos el siguiente mensaje
            } else {

                res.status(403).send({ status: 'ERR', data: 'Usuario NO ES admin' })

            }

            // Sino esta Autenticado devolvemos el siguiente mensaje 
        } else {

            res.status(401).send({ status: 'ERR', data: 'Usuario no autorizado' })

        }

    } catch (err) {
        res.status(500).send({ status: 'ERR', data: err.message })
    }
}


// 1) Endpoint para AUTENTICAR con JWT y hacer "login" de un Usuario 
// IMPORTANTE: Los Datos de Usuario estan llegando a la ruta via POST desde la plantilla "login.handlebars"
router.post('/login', async (req, res) => {

    //console.log(req.body) // Para verificar todo lo que esta llegando la peticion POST

    try {

        // Desestructuramos lo que viene en el body via post
        const { email, password } = req.body
        //console.log(password)

        // Buscando en la BD si existe un usario con el email pasado por el cliente
        const userInDB = await userController.getByEmail(email)
        //console.log(userInDB.password)

        // Validamos los Datos de Usuario contra la BD
        if (userInDB !== null && isValidPassword(password, userInDB.password)) {

            
            // *** Utilizando JWT ***
            // la funcion generateToken() tiene 2 parametros
            // Parametro 1: le pasamos los Datos de usuario 
            // Parametro 2: la duracion del token (tiempo de vida que va a tener) en el formato que me pide JWT
            const access_token = generateToken({ username: userInDB.email, admin: true }, '1h')

            //req.headers.authorization= access_token
            
            //enviamos el token al cliente
            //console.log(req.headers)

            //res.status(200).send({ status: 'OK', data: access_token })

            // Le paso el Token por la url al Cliente 
            res.redirect(`/products?access_token=${access_token}`)
            

        } else {

            // OJO aca se hace un render y no un redirect 
            // Como no se pudo loguear bien vuelve a renderizar la vista "/login"
            res.render('login', {})

        }


    } catch (err) {
        res.status(500).send({ status: 'ERR aca', data: err.message })
    }

    //----- Rutas para USAR del Lado del cliente -----------
    // Para mostrar: http://localhost:5000/api/sessions/login 

})


// 2) Endpoint Cerrar la Session/destruir de UN Usuario "login" - SOlO SIRVE PARA express-session
router.get('/logout', async (req, res) => {

    //console.log(req.session) // Para verificar todo lo que esta llegando la req.session

    try {

        // req.session.destroy nos permite destruir la sesión
        // De esta forma, en la próxima solicitud desde ese mismo navegador, se iniciará
        // desde cero, creando una nueva sesión y volviendo a almacenar los datos deseados.
        // .destroy requiere que se le pase un callback (err) =>{} para poder ejecutarse

        // IMPORTANTE: No es necesario hacer Nada mas xq el Modulo de session identifica que esta cerrando la session de este un usuario en especifico y en caso de hacer un error en el CERRADO lo reporta el mismo 
        req.session.destroy((err) => {

            // Si existe un error en proceso de logout lo reporto 
            if (err) {

                res.status(500).send({ status: 'ERR', data: err.message })

                // Sino devuelvo el mensaje exitoso
            } else {

                // Respuesta vieja 
                //res.status(200).send({ status: 'OK', data: 'Sesión finalizada' })

                // Al cerrar la session redirecciono a la "/login"
                res.redirect("/login")

            }
        })
    } catch (err) {
        res.status(500).send({ status: 'ERR', data: err.message })
    }

    //----- Rutas para USAR del Lado del cliente -----------
    // Para mostrar: http://localhost:5000/api/sessions/logout

    // Nota: esta ruta se una para LIMPIAR LA sesion INICIAZADO con la ruta http://localhost:5000/api/sessions
    // Y ARRANCA todo desde CERO NUEVAMENTE
})


// 3) Endpoint "privado", solo visible para un Usuario con Role de "admin" - SOlO SIRVE PARA express-session
router.get('/admin', auth, async (req, res) => {

    console.log(req.session) // Para verificar todo lo que esta llegando al req.session

    try {
        res.redirect('/profile')

    } catch (err) {

        res.status(500).send({ status: 'ERR', data: err.message })

    }

    //----- Rutas para USAR del Lado del cliente -----------
    // Para mostrar: http://localhost:5000/api/sessions/admin
})


// 4) Endpoint para Resturar el password de UN Usuario ya Existente - Trabajando con Modulo bcrypt
// IMPORTANTE: Los Datos de Usuario estan llegando a la ruta via POST desde la plantilla "login.handlebars"
router.post('/restore', async (req, res) => {

    //console.log(req.body) // Para verificar todo lo que esta llegando la peticion POST

    try {

        // Recuperamos del body los datos de usuario ingresados, 
        const { email, password } = req.body

        if (email.length === 0 || password.length === 0) {

            res.redirect('/restore', {})

        }

        // Buscando en la BD si existe un usario con el email pasado por el cliente
        const userInDB = await userController.getByEmail(email)
        //console.log(userInDB)
        //console.log(userInDB.email)
        //console.log(userInDB.password)

        // Restaurando el password del usuario 
        const newPass = {
            password: createHash(password)
        }

        // Actualizando en la BD el password del usuario 
        const passUpdate = await userController.updateUserPass(userInDB.email, newPass.password)

        //console.log(passUpdate.process)

        if (passUpdate.process) {

            // Aca codifico la respuesta que voy a enviar la URL - como Erro - para que no se vea en la URL
            const b64error = btoa(JSON.stringify(passUpdate.process))
            return res.redirect(`/restore?passUpdate=${b64error}`)
        }



    } catch (err) {
        res.status(500).send({ status: 'ERR', data: err.message })
    }

    //----- Rutas para USAR del Lado del cliente -----------
    // Para mostrar: http://localhost:5000/restore

    // Nota: Ruta para Restaurar el password de usurio usando el modulo - bcrytp

})



export default router