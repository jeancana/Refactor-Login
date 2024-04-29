
// ******** CONTROLLERS para la Creacion de Carritos con Productos - PERSISTENCIA DE ARCHIVOS EN MongoDB ********* 

// Importando el cartModel
// Al importar el cartModel nos traemos todo los metodos de la libreria mongoose 
import Cart from '../models/Cart.model.js'


export class CartController {
    
    constructor() {
        // Creo el constructor y lo dejo vacio
    }
    

    //  METODO CREATE = Agregando un carrito a la BD
    async addCart(newCart) {
        
        //console.log(`es addCart --->: `, newCart)
        
        try {
            
            return await Cart.create(newCart)
            
        } catch (err) {
            
            return err.message
            
        }
    }
    
    
    // METODO READ =  Leyendo todos los Carritos creados en la BD
    async getCarts() {
        try {
            
            // uso el metodo .find() que me proporciona mongoose 
            return await Cart.find().lean()
        
            
        } catch (err) {
            
            return err.message
            
        }
        
    }
    
    
    // METODO READ BY ID = Leyendo un(1) Carrito de la BD por su ID
    async getCartById(id) {
        
        try {
            
            // uso el metodo .findById(id) que me proporciona mongoose 
            const cart = await Cart.findById(id)

            // Aca hacemos una validacion ternaria a modo de control dentro del return
            return cart === null
                ? 'No se encuentra el Carrito'
                // Usamos el metodo format() creado por nosotros para poder poblar el carrito de forma correcta 
                : await cart.format()

        } catch (err) {

            return err.message
        }
    }


    // UPDATE = actualizar un Carrito por su ID en la BD
    // Recibe 2 parametros: 
    // El 1er "id" del carrito a actualizar
    // El 2do "newContent" el objeto con la informacion a actualizar
    async updateCart(id, newContent) {

        try {

            // uso el metodo .findByIdAndUpdate() que me proporciona mongoose
            const cart = await Cart.findByIdAndUpdate(id, newContent)
            return cart

        } catch (err) {

            return err.message
        }
    }


    // DELETE = Borrar un producto de la BD
    async deleteCartById(id) {
        try {

            // uso el metodo .findByIdAndDelete() que me proporciona mongoose
            const cart = await Cart.findByIdAndDelete(id)
            return cart

        } catch (err) {

            return err.message

        }
    }

}


