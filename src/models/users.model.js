
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

   
   // INDICE = Primary-Key
   // IMPORTANTE: Desde el Modelo le organizo y centralizo los INDICES que requiero Crear para mejorar la busqueda
   // Para Entender la Importancia de los INDICES = index
   // Agrego UN INDICE NUEVO (indexacion) en el campo firstName, 
   //mongo se encarga internamente de crear el indice en la BD Y se acelera la busqueda(mejora)
   first_name: { type: String, required: true, index: true },
   last_name: { type: String, required: true }, 
   email: { type: String, required: true }, 
   age: { type: Number },
   gender: { type: String, required: false },
   password: { type: String, required: true },
   cart: { type: mongoose.Schema.Types.ObjectId, ref: 'Cart' },
   role: { type: String, default: 'user' }

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