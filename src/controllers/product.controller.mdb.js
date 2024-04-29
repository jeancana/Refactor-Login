
// ******** CONTROLLERS para la Creacion de Productos - PERSISTENCIA DE ARCHIVOS EN MongoDB *********

// Importando el productModel
// Al importar el productModel nos traemos todo los metodos de la libreria mongoose 
import Product from '../models/Product.model.js'

export class ProductsController {
    
    constructor() {
        // Creo el constructor y lo dejo vacio
    }

    // METODO CREATE = Agregando un Producto a la BD
    async addProduct(product) {
        
        try {
            
            await Product.create(product)
            
            return "Producto agregado"

        } catch (err) {
            
            return err.message

        }
    }

    // METODO READ =  Leyendo el lista de productos y realizo una Paginacion de los mismos  
    async getProducts(limit, page, sort, description) {
        
        // 1er Parametro para que le Asigno al paginado 
        const criteria = {}
        if (description) {
            criteria.description = description
        }

        // 2do Parametro Filtros que van a condicionar mi paginacion 
        const pagination = {
            page: parseInt(page) || 1,
            limit: parseInt(limit) || 10,
            sort: { price: ['asc', 'desc'].includes(sort) ? sort : 'asc' },
            lean: true,
            select: ['_id', 'title', 'price', 'stock', 'description', 'thumbnail', 'code']
        }

        try {

            // Usando el Metodo .paginate() proporcionado por la libreria mongoose-paginate-v2
            const products = await Product.paginate(criteria, pagination)
            return products

        } catch (err) {

            return err.message
        }

    }

    // METODO READ BY ID = Leyendo un(1) producto de la BD por su ID 
    async getProductById(id) {
        
        try {

            // uso el metodo .findById(id) que me proporciona mongoose
            const product = await Product.findById(id)
            
            // Aca hacemos una validacion ternaria a modo de control dentro del return
            return product === null ? 'No se encuentra el producto' : product

        } catch (err) {
            return err.message
        }
    }

    // METODO UPDATE = actualizar un Producto por su ID en la BD
    // tiene 2 parametros: 
    // El 1er la paso ID del producto a actualizar
    // El 2do le paso el objeto con la informacion a actualizar
    async updateProduct(id, newContent) {

        try {

            // uso el metodo .findByIdAndUpdate() que me proporciona mongoose
            const procedure = await Product.findByIdAndUpdate(id, newContent)
            return procedure

        } catch (err) {

            return err.message
        }
    }

    // METODO DELETE = Borrar un producto de la BD
    async deleteProductById(id) {
        try {

            // uso el metodo .findByIdAndDelete() que me proporciona mongoose
            const procedure = await Product.findByIdAndDelete(id)
            return procedure

        } catch (err) {

            return err.message

        }
    }
  
}