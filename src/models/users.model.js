/**
   
   Coleccion (NoSQL) = Tabla (SQL)
   
   MODELO =  Un Archivo con la descripcion Estructurada/ordenada y Jerarquica de una COLECCION(NoSQL)

   *** Es un Archivo con el que le digo a MongoDb como tengo Organizado los Datos dentro mi coleccion *** 
   *** Se Debe tener un Modelo por cada Coleccion que voy a manejar
 
   - Creacion del MODELO para la Coleccion users: 
   Aca haremos el modelo que usara Mongoose,
   que nos permite "describir" los datos que vamos manejar 
   y Preparar la organización de la colección en la base de datos de MongoDB

*/

// *** PASO 1: Importar la libreria de Mongoose 

import mongoose from 'mongoose'//aca importamos la libreria xq necesitamos usar los metodos mongoose.model() y mongoose.Schema()


import mongoosePaginate from 'mongoose-paginate-v2'// importamos la libreria paginate de mongoose y paginamos la lista de usuario que ahora son 5000 


// IMPORTANTE: agregar esta línea SIEMPRE para no tener problemas con algunas configuraciones predeterminadas de Mongoose
mongoose.pluralize(null)


// *** PASO 2: la colección a Trabajar la que llamamos "users" dentro de la DB(MongoDB) y tiene el esquema indicado debajo

// 2.1) IMPORTANTE: El nombre que asignemos en el Archivo users.models.js a la "const collection" desde ser EXACTAMENTE IGUAL al nombre que pusimos cuando creamos la "coleccion=users" dentro "BD=coder_55605" en MongoDB-Compas 

const collection = 'users'// Esta la coleccion creada "coleccion=users" dentro "BD=coder_55605" en MongoDB-Compas 

// 2.2) Aca diseñamos el esquema que va a tener la coleccion 
const schema = new mongoose.Schema({

   // Aca dentro delineamos el Schema(esquema) con el funciona la Coleccion "users"
   // IMPORTANTE: Desde el Modelo le organizo y centralizo los INDICES que requiero Crear para mejorar la busqueda
   // INDICE = Primary-Key
   
   // Para Entender la Importancia de los INDICES = index
   first_name: { type: String, required: true, index: true },// Agregando UN INDICE NUEVO (indexacion) en el campo firstName, mongo se encarga internamente de crear el indice en la BD Y se acelera la busqueda (mejora)
   
   last_name: { type: String, required: true }, // le estoy pasando un Objeto como valor a la propiedad(clave)
   email: { type: String, required: true }, 
   password: { type: String, required: true },

})


// 2.3) Importamos mongoose-paginate-v2 y lo activamos como plugin en el schema, para tener disponible
// el método paginate() en las consultas
schema.plugin(mongoosePaginate)

// 2.4) Aca Creamos el Modelo a Exportar

// - El modelo tiene 2 parametros: 
// - En el Parametro Nro1: le paso la Constante "collection" 
// - En el Parametro Nro2: le paso la Constante "schema"
const usersModel = mongoose.model(collection, schema)

// 2.4) Habilitamos para Exportar el usersModel(modelo de Mongoose)
export default usersModel