
// *** PASO 1: importando librerias 

// Importo la libreria de Mongoose para poder usar los metodos mongoose.model() y mongoose.Schema()
import mongoose from 'mongoose'
 
// importamos la libreria paginate de mongoose y paginamos la lista de productos
import mongoosePaginate from 'mongoose-paginate-v2'

// IMPORTANTE: agregar esta línea SIEMPRE para no tener problemas con algunas configuraciones predeterminadas de Mongoose
mongoose.pluralize(null)


// *** PASO 2:  Creando el Modelo a Trabajar lo llamamos "Product" 

// 2.1) IMPORTANTE: El nombre que asignemos en el Archivo Product.model.js y en la constante "collection" debe ser EXACTAMENTE IGUAL al nombre que pusimos cuando creamos la "coleccion=Product" dentro "BD=ecommerce" en MongoDB-Compas/Atlas 

const collection = 'Product'// Debe coincidir con la "coleccion=Product" dentro "BD=ecommerce" en MongoDB-Compas 

// 2.2) Aca diseñamos el esquema que va a tener la coleccion 
const schema = new mongoose.Schema({

   // Aca dentro delineamos el Schema(esquema) con el funciona la Coleccion "Product"
   title: { type: String, required: true }, // le estoy pasando un Objeto como valor a la propiedad(clave)
   category: { type: String, required: false },
   price: { type: Number, required: true },
   thumbnail: { type: String, required: false },
   code: { type: String, required: true },
   stock: { type: Number, required: true }

}) 


// 2.3) Importamos mongoose-paginate-v2 y lo activamos como plugin en el schema, para tener disponible
// el método paginate() en las consultas
schema.plugin(mongoosePaginate)

// 2.4) Aca Creamos el Modelo a Exportar
// - El modelo tiene 2 parametros: 
// - En el Parametro Nro1: le paso la Constante "collection" 
// - En el Parametro Nro2: le paso la Constante "schema"

const productsModel = mongoose.model(collection, schema)

// 2.5) Habilitamos para Exportar el productModel(modelo de Mongoose)
export default productsModel


