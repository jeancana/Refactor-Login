

// *** PASO 1: importando librerias 

// Importo la libreria de Mongoose para poder usar los metodos mongoose.model() y mongoose.Schema()
import mongoose from 'mongoose'

// importamos la libreria paginate de mongoose y paginamos la lista de productos
import mongoosePaginate from 'mongoose-paginate-v2' 

// Importamos el Product.model.js para poder hacer el poblado dentro del carrito 
import Product from '../models/Product.model.js'

// IMPORTANTE: agregar esta línea SIEMPRE para no tener problemas con algunas configuraciones predeterminadas de Mongoose
mongoose.pluralize(null)


// *** PASO 2:  Creando el Modelo a Trabajar lo llamamos "Cart" 

// 2.1) IMPORTANTE: El nombre que asignemos en el Archivo cart.model.js y en la constante "collection" debe ser EXACTAMENTE IGUAL al nombre que pusimos cuando creamos la "coleccion=Cart" dentro "BD=ecommerce" en MongoDB-Compas/Atlas 

const collection = 'Cart' // Debe coincidir con la "coleccion=Cart" dentro "BD=ecommerce" en MongoDB-Compas  

// 2.2) Aca diseñamos el esquema que va a tener la coleccion 
const schema = new mongoose.Schema({

    // Aca dentro delineamos el Schema(esquema) con el funciona la Coleccion "Cart"
    products: {
        type: [
            {
                producto: { type: mongoose.Schema.Types.ObjectId, ref: 'Product' },
                cantidad: { type: Number }
            }
        ]
    },

    // - products =  Es el objeto Principal 
    // - type = Es el array que va contener objetos con la siguiete info:los Ids de mongoose
    //   1) producto = { type: [mongoose.Schema.Types.ObjectId], ref: 'products' }, ref a la colección 'Product' en la BD
    //   2) Cantidad = { type: Number, }, cantidad de producto agregados al carrito

})

// 2.3) POPULATE USANDO Populate dentro del MODEL 
// Nota: El Populate solo lo estamos usando en Metodo getcarts() - para consultar todo los carritos
schema.pre('find', function () {

    this.populate({ path: 'products.producto', model: Product });

})

// 2.4) activamos mongoose-paginate-v2 como plugin en el schema, para tener disponible
// el método paginate() en las consultas
schema.plugin(mongoosePaginate)


// 2.5) CREAMOS NUESTRP PROPIO METODO ".format()" PARA POBLAR(populate) el Modelo Cart 
// Nota: el metodo .format() Nos permiter tener siempre el conrtol sobre la instancia del Modelo Cart 
schema.methods.format = async function () {
    let total = 0

    const products = []

    for (let i = 0; i < this.products.length; i++) {
        
        const product = await Product.findById(this.products[i].producto)
        total += product.price * this.products[i].cantidad
        
        products.push({
            product: {
                id: product.id,
                title: product.title,
                price: product.price,
                code: product.code,
                stock: product.stock,
                description: product.description,
                thumbnail: product.thumbnail,
            },
            cantidad: this.products[i].cantidad,
        })
    }

    return {
        id: this.id,
        products,
        total,
    }
}

// 2.6) Aca Creamos el Modelo a Exportar
// - El modelo tiene 2 parametros: 
// - En el Parametro Nro1: le paso la Constante "collection" 
// - En el Parametro Nro2: le paso la Constante "schema"

const cartsModel = mongoose.model(collection, schema)

// 2.7) Habilitamos para Exportar el usersModel(modelo de Mongoose)
export default cartsModel

// Otra Forma de exportar el Modelo
//export default mongoose.model(collection, schema)


