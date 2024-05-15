
import { Router } from 'express'

import { CartController } from '../controllers/cart.controller.mdb.js'
import Product from '../models/Product.model.js'
import { authToken } from '../utils.js'

const router = Router()

// Paso 2: Generando una nueva Intanscia - Persistencia de Archivos con MongoDB
const controller = new CartController()

// ************* Paquete de Rutas de /api/products ********************

// Nota: Fortalecimos el Codigo agregando try/catch en todas las rutas y respetamos los codigos de Estado


// *** 1.1) Read - Endpoint para leer/Consultar todos los Carritos Existentes en la DB - Formato JSON
router.get('/', async (req, res) => {

    //console.log(req.credentials) 
    //console.log(req.headers)
    try {

        // Aca Mandamos la respuesta al cliente con el listado de productos encontrados en BD
        res.status(200).send({ status: 'OK. Mostrando Listado de Carritos', data: await controller.getCarts() })

    } catch (err) {

        res.status(500).send({ status: 'ERR', data: err.message })

    }
})


// *** 1.2) Read - Endpoint para leer/Consultar Un(1) Carrito por su ID en BD - Con POSTMAN
router.get('/:cid', async (req, res) => {

    try {

        // Desestructuramos lo que nos llega req.params
        const { cid } = req.params

        //IMPORTANTE: Aca verifico que solo le estoy pasando el valor(ID)  
        console.log(cid)

        // Paso 3: Usando el Metodo .getCartById() disponible en archivo cart.controller.mdb.js
        const result = await controller.getCartById(cid)

        // Aca Mandamos la respuesta al cliente con el Carrito encontrado 
        res.status(200).send({ status: 'Ok. Mostrando Carrito Selecionado ', data: result })

    } catch (err) {

        res.status(500).send({ status: 'ERR', data: err.message })

    }

    //----- Rutas para USAR del Lado del cliente -----------
    // Para mostrar: http://localhost:5000/api/carts/65ba888487d6c36549545995

})


// *** 2) Create - Endpoint para Crear un Nuevo Carrito de productos Vacio o Con productos- Con POSTMAN  
router.post('/', async (req, res) => {

    console.log("Esto me llego por Fetch desde el cliente",req.body)// Verificando lo que viene por el body
    
    const products = req.body // Asignando lo que viene por body a una constante
    //console.log("products - Aca", (products)

    // Verificamos y sino mandan nada por el Body Creamos un carrito vacio 
    if (!products) {

        try {

            const newContent = {
                products: []
            }

            const result = await controller.addCart(newContent)

            return res.status(200).send({ status: 'ok - Carrito Vacio Creado', data: result })

        } catch (err) {

            res.status(500).send({ status: 'ERR', data: err.message })

        }

    } else {

        for (let i = 0; i < products.length; i++) {
            const { producto, cantidad } = products[i]

            // Validate product
            try {
                const product = await Product.findById(producto)

                // Validate positive quantity
                if (cantidad < 1) {
                    return res.status(400).send({ status: 'BAD REQUEST', data: `Cantidad must be greater than 1` })
                }

                if (cantidad > product.stock) {
                    return res.status(400).send({ status: 'BAD REQUEST', data: `Cantidad must be less than ${product.stock}` })
                }
            } catch {
                return res.status(400).send({ status: 'BAD REQUEST', data: `Product ID not found: ${producto}` })
            }
        }

        try {

            // Paso 3: Usando el Metodo .addProduct() disponible en archivo product.controller.mdb.js

            const result = await controller.addCart(products)

            // Aca Mandamos la respuesta al cliente
            return res.status(200).send({ status: 'OK. Carrito Creado', data: result })

        } catch (err) {

            res.status(500).send({ status: 'ERR', data: err.message })

        }



    }

})


// *** 3) Update - Endpoint par Agregar/Actualizar los productos a un Carrito en la DB - Con POSTMAN
router.put('/:cid', authToken, async (req, res) => {

    try {

        console.log(req.credentials)
        // Desestructuramos lo que nos llega req.params
        const { cid } = req.params

        //IMPORTANTE: Aca verifico que solo le estoy pasando el valor(ID) 
        console.log('/api/carts/${pid} - req.params ',cid)
        console.log('del fetch - req.body ', req.body)

        // Desestructuramos el req.body 
        const { products, total } = req.body


        // Verificamos y Validamos los valores recibidos
        if (!products || !total) {
            return res.status(400).send({ status: 'ERR', data: 'Faltan campos obligatorios' })
        }

        // IMPORTANTE: Aca tenemos un else{} intrinsico por la lectura en cascada 

        // Creamos un Nuevo Array con los de productsIdArray
        const newContent = {

            products: products,
            total: total

        }

        // Verificando que esta dentro de newContent
        //console.log(newContent)

        // Paso 3: Usando el Metodo .updateCart() disponible en archivo product.controller.mdb.js
        const result = await controller.updateCart(cid, newContent)

        // Aca Mandamos la respuesta al cliente
        res.status(200).send({ status: 'OK. Product Updated', data: result })

    } catch (err) {

        res.status(500).send({ status: 'ERR', data: err.message })

    }

})


// *** 4) Delete - Borrando todo los Productos del Carrito (dejando el carrito vacio) de la DB - Con POSTMAN
router.delete("/:cid", async (req, res) => {

    try {

        // Asignamos a id el ID que nos llega req.params
        const { cid } = req.params

        //IMPORTANTE: Aca verifico que solo le estoy pasando el valor(ID) 
        console.log(cid)

        const newContent = {

            products: [],
            total: ' '

        }

        // Paso 3: Usando el Metodo .deleteProductById() disponible en archivo product.controller.mdb.js
        const result = await controller.updateCart(cid, newContent)

        // Aca Mandamos la respuesta al cliente
        res.status(200).send({ status: 'OK. Cart Deleted', data: result })

    } catch (err) {

        res.status(500).send({ status: 'ERR', data: err.message })

    }
})


// *** 5) Delete - Endpoint para Borra un Producto agregado al Carrito - Con POSTMAN
router.delete('/:cid/products/:pid', async (req, res) => {

    try {

        // Desestructuramos lo que nos llega req.params
        const { cid, pid } = req.params

        //IMPORTANTE: Aca verifico que solo le estoy pasando el valor(ID)
        console.log(cid)
        console.log(pid)

        // Verificamos y Validamos los valores recibidos
        if (!cid || !pid) {
            return res.status(400).send({ status: 'ERR', data: 'Faltan campos obligatorios' })
        }

        // IMPORTANTE: Aca tenemos un else{} intrinsico por la lectura en cascada 

        // Usando el Metodo .getCartById() para encontar el carrito
        const cart = await controller.getCartById(cid)

        // Desestructuramos el Carrito encontrado
        const { _id, products, total } = cart

        // Verificando el contenido de "products"
        console.log(typeof products)
        console.log(Array.isArray(products))// Verificando si es un Array 


        // Modificando Copia Profunda 
        const products2 = JSON.parse(JSON.stringify(products))

        // Eliminando un producto del carrito
        const deleteProductoOncart = products2.filter(item => item._id !== pid)

        // Creamos un Nuevo Array con los productos que NO fueron eliminados del carrito
        const newContent = {

            _id: _id,
            products: deleteProductoOncart,
            total: total

        }

        // Verificando el nuevo contenido del Array
        console.log(newContent)

        // Pisando el Carrito Viejo por uno nuevo con los productos que no fueron eliminados 
        const result = await controller.updateCart(cid, newContent)

        // Aca Mandamos la respuesta al cliente
        res.status(200).send({ status: `OK. Product Deleted On Cart ID: ${cid}`, data: result })

    } catch (err) {

        res.status(500).send({ status: 'ERR', data: err.message })

    }

})


export default router


