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

const initPassport = () => {

    // Función utilizada por la estrategia registerAuth
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

    // Función utilizada por la estrategia restoreAuth
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

    // Función utilizada por la estrategia githubAuth
    const verifyGithub = async (accessToken, refreshToken, profile, done) => {

        // Aca nos llega nos datos de perfil que viene de GITHUB
        // Y son los datos que vamos a poder usar 
        //console.log(profile)
        //console.log(profile._json.email)
        
        try {

            // Buscamos si existe en nuestra base de BD ya existe un usuario con ese mi mail que llego de Github

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
    
    // IMPORTANTE: Creamos estrategia local de autenticación para registro
    // Es lo primero que se debe hacer CREAR LA ESTRATEGIA 
    passport.use('registerAuth', new LocalStrategy({
        passReqToCallback: true,
        usernameField: 'email',//Esto debe ser igual a atributo name:email en la plantilla "register.handlebar"  
        passwordField:'password'//Esto debe ser igual a atributo name:password en la plantilla "register.handlebar"
    }, verifyRegistration)) // Paso la Callback verifyRegistration a la estrategia Ya Creada 


    // Creamos estrategia local de autenticación para restauración de clave 
    passport.use('restoreAuth', new LocalStrategy({
        passReqToCallback: true,
        usernameField: 'email',
        passwordField: 'password' 
    }, verifyRestoration))
        

    // Creamos estrategia para autenticación externa con Github
    passport.use('githubAuth', new GithubStrategy({
        clientID: 'Iv1.09037589aec6251b',
        clientSecret: '22d28cd7db82b3800e8670794d5c9ff15d7ab7c9',
        callbackURL: 'http://localhost:5000/api/sessions/githubcallback'
    }, verifyGithub)) // la funcion esta creada arriba para poder tener orden 



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