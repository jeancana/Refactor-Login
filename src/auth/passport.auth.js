/**
 * passport.local siempre requiere 2 cosas: username y password
 * 
 * podemos usar el parámetro usernameField para cambiar el nombre del campo que
 * manejaremos como usuario (email en nuestro caso)
 * 
 * passport utiliza un callback done():
 *  - parámetro 1: el error (null indica que no hay error)
 *  - parámetro 2: el objeto con datos de usuario que se devuelve en la respuesta
 *      - done(null, user) -> user tendrá los datos de usuario
 *      - done(null, false) -> no hay error pero los datos de usuario no se devuelven
 * 
 * passport.use() nos permite configurar distintas estrategias
 */


// El modulo passport me permite autenticar a traves de diferentes Servicios y Estrategias
// Algunas Estrategias de Autenticacion que nos permite el modulo "passport"
/* 
    1.- Autenticacion de usuario desde una BD local (LocalStrategy) - Datos propios ***como venimos haciendo***
    2.- Autenticacion de usuario con cuenta de Github
    3.- Autenticacion de usuario con cuenta de Google
    4.- Autenticacion de usuario con cuenta de Facebook
*/

import passport from 'passport'
import LocalStrategy from 'passport-local'// En este caso vamos a usar la estragia de autenticacion LocalStrategy
import GithubStrategy from 'passport-github2' // Estrategia para autenticar usuario con los datos de la Ctta Github
import userModel from '../models/users.model.js'
import { createHash, isValidPassword } from '../utils.js'

// En Caso estoy importando todo el Modulo JWT de passport 
// Xq necesitamos usar de elementos para trabajar en la estrategia 
// Elemento Nro 1: jwt.Strategy - para Crear una nueva Estrategia
// Elemento Nro 2: jwt.ExtractJwt - Para poder Manipular las Cookies con el Modulo passport
// xq passport NO tiene acceso directo al req.cookies en forma AUTOMATICA 
// Vamos a Tener que trabajar con el Modulo CookieParser Adicionalmente "app.use(cookieParser('secretkeyAbc123'))"
import jwt from 'passport-jwt' //Permite Modulo passport manejar JWT (una estrategia mas) sin usar el archivo utils.js

const initPassport = () => {

    // done en passport es = a lo que es next en los middleware  

    // 1.1) Callback utilizada por la estrategia registerAuth
    const verifyRegistration = async (req, username, password, done) => {


        // Nota: El paramentro username = email, se usa busca el usuario en el .findOne()

        try {
            const { first_name, last_name, email, gender } = req.body

            if (!first_name || !last_name || !email || !gender) {
                return done('Se requiere first_name, last_name, email y gender en el body', false)
            }

            const user = await userModel.findOne({ email: username })

            // El usuario ya existe, llamamos a done() para terminar el proceso de
            // passport, con null (no hay error) y false (sin devolver datos de usuario)
            if (user) return done(null, false)

            const newUser = {
                first_name,
                last_name,
                email,
                gender,
                password: createHash(password)
            }

            const process = await userModel.create(newUser)

            return done(null, process)
        } catch (err) {
            return done(`Error passport local: ${err.message}`)
        }
    }

    // 2.1) Callback utilizada por la estrategia restoreAuth
    const verifyRestoration = async (req, username, password, done) => {
        try {
            if (username.length === 0 || password.length === 0) {
                return done('Se requiere email y pass en el body', false)
            }

            const user = await userModel.findOne({ email: username })

            // El usuario no existe, no podemos restaurar nada.
            // Llamamos a done() para terminar el proceso de
            // passport, con null (no hay error) y false (sin devolver datos de usuario)
            if (!user) return done(null, false)

            const process = await userModel.findOneAndUpdate({ email: username }, { password: createHash(password) })

            return done(null, process)
        } catch (err) {
            return done(`Error passport local: ${err.message}`)
        }
    }

    // 3.1) Callback utilizada por la estrategia githubAuth
    const verifyGithub = async (accessToken, refreshToken, profile, done) => {

        // Aca nos llega nos datos de perfil que viene de GITHUB
        // Y son los datos que vamos a poder usar 
        //console.log(profile)
        //console.log(profile._json.email)

        try {

            // Buscamos si existe en nuestra base de BD ya existe un usuario con ese mi mail que llego de Github

            // PARCHE 1: Tuve que hacer Trampa para que funcionara xq YO MICHELL Puso su correo como "privado"
            // En mi perfil de Github y cuando llegando los datos de profile el campo llega null
            // const user = await userModel.findOne({ email:'jeancanache@gmail.com' })// HARCODEADOR PARA QUE FUNCIONE

            // UN Parche 2: que invente PARA PODER HACER FUNCIONAR EL LOGUIN CON GITHUB
            //const name_parts_for_search = profile._json.name.split(' ')
            //const user = await userModel.findOne({ first_name: name_parts_for_search[0]  })


            // ESTA ES LA "FORMA CORRECTA"
            const user = await userModel.findOne({ email: profile._json.email })

            // Sino existe un usuario con ese mail en mi BD, entonces creamos nosotros el usuario en nuestra BD
            if (!user) {

                const name_parts = profile._json.name.split(' ') // Tomamos los datos de Profile y le aplicamos un .split()
                const newUser = {
                    first_name: name_parts[0],
                    last_name: name_parts[1],
                    email: profile._json.email,// Usamos el que no nos llego en el profile de Github
                    gender: 'NA', // No aplica xq Github no proporciona estos datos
                    password: ' ' // Esta vacio xq el usurio se autentica con ctta de Github
                }

                // Procedemos a Crear el usuario en nuestra BD
                const process = await userModel.create(newUser)

                // Retornamos los Datos Procesados 
                return done(null, process)

            } else {

                // Si existe un Usuario con el mismo mail que tomamos de Github en nuestra BD y lo retornamos
                done(null, user)

            }
        } catch (err) {

            return done(`Error passport Github: ${err.message}`)

        }
    }


    /**
    // 4.1) Callback utilizada por la estrategia jwtAuth
    * Si passport pudo extraer correctamente el token, devuelve el payload 
    * (datos útiles contenidos en él), sino devuelve el error correspondiente
    */
    const verifyJwt = async (payload, done) => {
        try {
            return done(null, payload);
        } catch (err) {
            return done(err);
        }
    }

    /**
     // 4.2) Pieza de codigo utilizada por la estrategia jwtAuth dentro de la Estrategia
     * Passport no opera con las cookies de forma directa, por lo cual creamos
     * una función auxiliar que extrae y retorna la cookie del token si está disponible
     */
    const cookieExtractor = (req) => {
        let token = null;
        if (req && req.cookies) token = req.cookies['cookie-JWT'];
        return token;
    }

    // 1) Estrategia local de autenticación para registro
    // Es lo primero que se debe hacer CREAR LA ESTRATEGIA 
    passport.use('registerAuth', new LocalStrategy({
        passReqToCallback: true,
        usernameField: 'email',//Esto debe ser igual a atributo name:email en la plantilla "register.handlebar"  
        passwordField: 'password'//Esto debe ser igual a atributo name:password en la plantilla "register.handlebar"
    }, verifyRegistration)) // Paso la Callback verifyRegistration a la estrategia Ya Creada 


    // 2) Estrategia local de autenticación para restauración de clave 
    passport.use('restoreAuth', new LocalStrategy({
        passReqToCallback: true,
        usernameField: 'email',
        passwordField: 'password'
    }, verifyRestoration))


    // 3) Estrategia para autenticación Externa con Github
    passport.use('githubAuth', new GithubStrategy({
        clientID: 'Iv1.09037589aec6251b',
        clientSecret: '22d28cd7db82b3800e8670794d5c9ff15d7ab7c9',
        callbackURL: 'http://localhost:5000/api/sessions/githubcallback'
    }, verifyGithub)) // la Callback esta creada arriba para poder tener orden 


    // 4) Estrategia para autenticación con JWT
    passport.use('jwtAuth', new jwt.Strategy({
        jwtFromRequest: jwt.ExtractJwt.fromExtractors([cookieExtractor]),
        secretOrKey: 'JWT-Backend_Key_Jwt' // Firma del token 
    }, verifyJwt)) // Aca pasamos el callback 



    // Métodos "helpers"(ayudasInterna) de passport para manejo de datos de sesión
    // Son de uso interno de passport, normalmente no tendremos necesidad de tocarlos.
    // Los Usa Internamente passport NO MODIFICARLOS
    passport.serializeUser((user, done) => {
        done(null, user._id)
    })
        
    passport.deserializeUser(async (id, done) => {
        try {
            done(null, await userModel.findById(id))
        } catch (err) {
            done(err.message)
        }
    })
}

export default initPassport